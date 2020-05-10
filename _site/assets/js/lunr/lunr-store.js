var store = [{
        "title": "Bof-server [100]",
        "excerpt":"Category: Binary Exploitation Today kids we learn how to write exploits for super-secure software: bof-server! nc 89.38.208.144 11112 (non-standard flag format) Challenge Files Write-up This is a standard buffer overflow shellcoding challenge. As usual, running checksec on the binary gives: Arch: amd64-64-little RELRO: Partial RELRO Stack: No canary found NX:...","categories": [],
        "tags": ["Timisoara CTF","Binary Exploitation"],
        "url": "http://localhost:4000/Bof-server/",
        "teaser":null},{
        "title": "Flag Manager Service [400]",
        "excerpt":"Category: Binary Exploitation Our spies found this flag manager service running on the ctf server. It needs a password tho, but I am sure you can handle it. nc 89.38.208.144 11115 Challenge Files Write-up Analysis of the binary with Ghidra shows this is a standard ret2libc buffer overflow. libc-2.27.so being...","categories": [],
        "tags": ["Timisoara CTF","Binary Exploitation"],
        "url": "http://localhost:4000/Flag-Manager-Service/",
        "teaser":null},{
        "title": "Hiss Hiss Python [50]",
        "excerpt":"Category: Binary Exploitation This snake likes to h1ss at its input. nc 89.38.208.144 11113 Challenge Files Write-up Vulnerability: https://blog.efiens.com/efiensctf2019-round2-write-ups/ Unlike Python 3, Python 2’s input() actually evaluates the input instead of taking it as a string. If we feed a command into input(), Python 2 will run the command, which...","categories": [],
        "tags": ["Timisoara CTF","Binary Exploitation"],
        "url": "http://localhost:4000/Hiss-Hiss-Python/",
        "teaser":null},{
        "title": "Pipes [200]",
        "excerpt":"Category: Reversing The program seems to smoke a lot. Challenge Files Write-up As usual, first we decompile the binary using Ghidra for analysis. The code below are the important parts of the decompilation: rol function: int rol(uchar *character,int max) { int i; i = 0; while (i &lt; max) {...","categories": [],
        "tags": ["Timisoara CTF","Reversing"],
        "url": "http://localhost:4000/Pipes/",
        "teaser":null},{
        "title": "Strange Jump[250]",
        "excerpt":"Category: Reversing This program likes to jump! Challenge Files Write-up Using Ghidra to decompile the binary, notice that there are a lot of functions. Most of the functions in the binary are placed to mislead and distract, and can be ignored. To find the function that contains the flag, look...","categories": [],
        "tags": ["Timisoara CTF","Reversing"],
        "url": "http://localhost:4000/Strange-Jump/",
        "teaser":null},{
        "title": "Swag [100]",
        "excerpt":"Category: Binary Exploitation The server only lets hackers in, not script kiddies. nc 89.38.208.144 11111 Challenge Files Write-up This is probably an unintended solution. Run strings on the binary and we get the following: /lib64/ld-linux-x86-64.so.2 libc.so.6 gets fflush exit srand puts time printf stdout __libc_start_main GLIBC_2.2.5 __gmon_start__ AWAVI AUATL []A\\A]A^A_...","categories": [],
        "tags": ["Timisoara CTF","Binary Exploitation"],
        "url": "http://localhost:4000/Swag/",
        "teaser":null},{
        "title": "Team Manager [300]",
        "excerpt":"Category: Binary Exploitation I found the team manager service used for Timisoara CTF. Do you think it is secure? nc 89.38.208.144 11114 Challenge Files Write-up Running the binary instantly shows this is a standard heap challenge: Welcome to the Timctf Team Manager 1: Add player 2: Remove player 3: Edit...","categories": [],
        "tags": ["Timisoara CTF","Binary Exploitation"],
        "url": "http://localhost:4000/Team-Manager/",
        "teaser":null},{
        "title": "Timisoara CTF 2019 Qualifiers",
        "excerpt":"Team Name: acsii  Position: 12  Score: 3726/5826   Challenge Writeups  Binary Exploitation  Hiss Hiss Python [50] Swag [100] Bof-server [100] Team Manager [300] Flag Manager Service [400]   Reversing  Pipes [200] Strange Jump [250]     ","categories": [],
        "tags": ["Timisoara CTF","CTF"],
        "url": "http://localhost:4000/Timisoara-CTF-2019-Qualifiers/",
        "teaser":null},{
        "title": "HATS CTF",
        "excerpt":"Name: MiloTruck  Position: 1  Score: 7232   Challenge Writeups  Binary Exploitation  ezprintf [496] babyvm-pwn [500]   Reversing  babyvm-re [500]     ","categories": [],
        "tags": ["HATS CTF","CTF"],
        "url": "http://localhost:4000/HATS-CTF/",
        "teaser":null},{
        "title": "babyvm-pwn [500]",
        "excerpt":"Category: Binary Exploitation Now the vm is hosted on a server, i feel like there is something hidden in the server too… nc challs.hats.sg 1308 Hint: Can you modify the return pointer? Challenge Files Write-up Before reading this writeup, I suggest reading the writeup for babyvm-re [500] if you have...","categories": [],
        "tags": ["HATS CTF","Binary Exploitation"],
        "url": "http://localhost:4000/babyvm-pwn/",
        "teaser":null},{
        "title": "babyvm-re [500]",
        "excerpt":"Category: Reversing You have stumbled across a interesting piece of code with seemingly random letters and numbers, can you help find what the key is? Hint: Slowly analyse the vm, try making sense of what each instruction does Challenge Files Write-up As usual, we run the binary provided first: Enter...","categories": [],
        "tags": ["HATS CTF","Reversing"],
        "url": "http://localhost:4000/babyvm-re/",
        "teaser":null},{
        "title": "ezprintf [496]",
        "excerpt":"Category: Binary Exploitation Printf is wonky. Time to exploit its wonkyness. nc challs.hats.sg 1304 Reading material: https://www.exploit-db.com/docs/english/28476-linux-format-string-exploitation.pdf Challenge Files Write-up This challenge is a standard format string challenge. Here’s the simplified decompilation of main: magic = 0; read(0,input,0x400); printf(input); if (magic != 0) { system(\"/bin/sh\"); } Obviously, the line printf(input);...","categories": [],
        "tags": ["HATS CTF","Binary Exploitation"],
        "url": "http://localhost:4000/ezprintf/",
        "teaser":null},{
        "title": "Cyberthon 2020",
        "excerpt":"Team Name: acsi-1  Position: 3  Score: 6856  Other honors: Winner of Data Science Category     ","categories": [],
        "tags": ["Cyberthon","CTF"],
        "url": "http://localhost:4000/Cyberthon-2020/",
        "teaser":null}]
