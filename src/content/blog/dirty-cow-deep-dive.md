---
title: "DirtyCoW - Deep Dive"
description: "Deep dive into a Linux CVE affecting the memory management subsystem"
pubDate: 2024-12-30
category: "Binary Exploitation"
readTime: "12 min read"
type: blog
tags: ["Binary Exploiting", "Race Condition", "Reversing", "Vulnerability Research", "Legacy"]
author: "0xl0w3"
---

# Overview
DirtyCow is a really old vulnerability that exploited an even older bug (goes back to 2005!) Discovered in 2016 while an incident investigation was taking place, this exploit took advantage on the fact that Copy On Write operations are not atomic and therefore, a Race Condition is theoretically possible, allowing Read Only mappings to be written.

In this post, exploitation details will not be discussed as it has been discussed in depth by many other security researchers and exploits have been heavily optimized. Therefore, in this post I will only cover the underlying details and reasons why this vulnerability happened

# Background
Before diving deep into the inner working of the exploit and the vulnerability, I will explain some crucial concepts that are necessary to understand why this was exploitable in first place.


## COW

`COW` stands for _Copy on Write_, and it is a kernel mechanism that kicks in when a process tries to write to a file. Since multiple processes might want to read from the same file, what the kernel does is allow them to read from the file in disk itself and, when a process wants to write to that file, it will create a private mapping and copy the file. After that, it will write to that file the specified data. This mechanism is implemented on the Memory Management Subsystem of the Linux kernel.

As you can see, this process is not atomic, it requires 2 operations:

- Map memory
- Write to memory

This will gain importance later on.

## madvise

`madvise` is a syscalll that allows developers to tell it how memory mappings will be used in the near future. We could use  `DONTNEED` to tell it that the memory mapping will not be used and therefore the kernel might free it at some point. A key thing to understand is that, future access to mappings that have been freed my `madvise(DONTNEED)` will result in pointing back to the original physical address of the mapping

### PoC show how madvise works

The following code shows how pointers to physical addresses work when

- Reading form the file
- Writing to the file
- `madvise`ing the mapping

```c
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>

#define PAGE_SHIFT 12
#define PFN_MASK ((1ULL << 55) - 1)

uint64_t virtual_to_physical(void *vaddr) {
    uint64_t vaddr_offset = (uint64_t)vaddr / getpagesize() * sizeof(uint64_t);
    uint64_t page_entry;
    
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1) {
        perror("open pagemap");
        return 0;
    }
    if (pread(fd, &page_entry, sizeof(uint64_t), vaddr_offset) != sizeof(uint64_t)) {
        perror("pread pagemap");
        close(fd);
        return 0;
    }
    close(fd);
    if (!(page_entry & (1ULL << 63))) {
        printf("Page not mapped to physical memory.\n");
        return 0;
    }
    uint64_t pfn = page_entry & PFN_MASK;
    return (pfn << PAGE_SHIFT) | ((uint64_t)vaddr & (getpagesize() - 1));
}

int main() {
    struct stat st;
    int f;
    void *map;

    f = open("testfile.txt", O_RDWR);
    if (f == -1) {
        perror("open");
        return 1;
    }

    fstat(f, &st);
    
    map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, f, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(f);
        return 1;
    }

    printf("Virtual address of the mapping: %p\n", map);
    printf("Content of the file: %s\n", (char *)map);

    uint64_t addr_before = virtual_to_physical(map);
    printf("Virtual addres %p points to Physical address 0x%llx\n", map, (unsigned long long)addr_before);

    strcpy((char *)map, "test");

    uint64_t addr_after = virtual_to_physical(map);
    printf("Virtual addres %p points to Physical address 0x%llx\n", map, (unsigned long long)addr_after);
    
    madvise(map,100,MADV_DONTNEED);
    dumy = (char *)map
    
    uint64_t addr_madvise = virtual_to_physical(map);
    printf("Virtual addres %p points to Physical address 0x%llx\n", map, (unsigned long long)addr_madvise);

    if (addr_before != addr_after) {
        printf("Copy-on-Write ha sido activado. Las direcciones físicas son diferentes.\n");
    } else {
        printf("Las direcciones físicas no cambiaron, algo salió mal.\n");
    }

    munmap(map, st.st_size);
    close(f);

    return 0;
}

```

![alt text](/images/deep-dive-dirtycow/image.png)


This diagram shows in a graphic way what is happening underneath.

When we first create the mapping and read from the file, the virtual address will point to where the original file is loaded in physical memory

![alt text](/images/deep-dive-dirtycow/image-1.png)

When we try to write to it, CoW kicks in, creating a different mapping for the changes to be done.

![alt text](/images/deep-dive-dirtycow/image-2.png)

When `madvise` is executed, the virtual address points back to the original physical address

![alt text](/images/deep-dive-dirtycow/image-3.png)


## Dirty bits

When the COW mechanism kicks in, the newly private page mappings allocated with write privileges will have a bit that indicates whether the mapping has been modified or not. If it is a file-backed mapping, it will be stored to disk.


# Vulnerability Technical Details

As in the previous article, we will use patch diffing here to find how the vulnerability was fixed in order to try to understand what was wrong:

![alt text](/images/deep-dive-dirtycow/image-4.png)

This was the commit message made by Linus. As he explains, the bug was well known and tried to fix it at some point, but incompatibility with some processors made him roll back. Back then, the attack was purely theoretical, but with time and more powerful machines, it became possible.

The fix was implemented by creating a new function to check if the `pte` will be writeable or not by checking if either
- The `pte` is already writeable
- The `pte` has been marked as dirty, it went through a `COW` cycle and it is forced

Then, some checks were implemented by using the newly created function

Lastly, a new flag was implemented to indicate if the page should undergo a `COW` cycle.

This fix works because now, for the kernel to unlock the `pte` and make it writeable again, the page should either be writeable or had gone through the full `COW` cycle. 

The following enumeration tries to explain how the timing happened before the fix:
1. Request access to a read-only page
2. Page Fault occurs, triggering `COW`
  3. `pte` is marked as read-only
  4. New mapping is created for the content to be copied to
  5. At this point, the attacker issues `madvise` calls, freeing the page that was allocated BUT NOT WRITTEN TO
  6. The write happens to the original read-only file instead of the private mapping.

Now, with the fix, the flow is the following:

1. Request access to a read-only page
2. Page Fault occurs, triggering `COW` and flag is added to mark `COW` is needed
  3. `pte` is marked as read-only
  4. New mapping is created for the content to be copied to
  5. At this point, the attacker issues `madvise` calls, freeing the page that was allocated BUT NOT WRITTEN TO
  6. It tries to write to the read-only file, but it does not comply with the checks, since it has not yet been marked as dirty and the `COW` flag has been set, therefore, it does not write to the page

# Conclusion

This vulnerability has been hard to undersand and document, primarly because most resources focus on the exploit and explaining at a high level how it worked, but not in the inner working of the mechanisms and why it was vulnerable in first place. If I'm honest, I still lack some knowledge and have some gaps of certain inner workings of the memory management subsystem of Linux. If you feel like you could help me out with this, please, do not doubt in contacting me through 0xl0w3@proton.me.

Thank you for reading and until the next one!!