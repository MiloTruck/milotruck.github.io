---
title: "I smell updates! [1986]"
--- 

**Category:** Internet of Things (IoT) 

## Challenge Description
>Agent 47, we were able to retrieve the enemy's security log from our QA technician's file! It has come to our attention that the technology used is a 2.4 GHz wireless transmission protocol. We need your expertise to analyse the traffic and identify the communication between them and uncover some secrets! The fate of the world is on you agent, good luck.
>
> **Flag Format:**`govtech-csg{derived-value}`

## Initial Analysis
We are provided with a `iot-challenge-3.pcap` file, which can be analysed using Wireshark. As usual, I use a simple `strings` command first to check for anything interesting:
```
Galaxy S7 edge
_tk
Bro: Dude did u ate my chips
/lib/ld-linu
x-armhf.so.3
(Too cool 4 u) TK: Emma owes me $36 for the dinner
|fUa
libc.so
exit
puts
stdin
printf
fgets
strlen
ibc_start_main
Boss: I will not be in the office
_gmon_start__
IBC_2.4
Boss: Can u help me check smth on my com real quick
```
It seems there is unencrypted data in the given file. We can tell there are two things to be extracted:
* Messages, such as `Bro: Dude did u ate my chips`
* An `ELF executable, ARM`, which can be seen from the presence of common glibc functions and `x-armhf.so.3`

## PCAP Analysis
*Keep in mind the focus is to find and extract those data bytes, and filter out all other packets*

By opening the pcap file in Wireshark, we see `ATT` and other protocols. As usual, we turn to Google for unfamiliar stuff.

From [this website](https://www.oreilly.com/library/view/building-bluetooth-low/9781786461087/3323a094-8c3b-4c99-b28a-b284745a61b5.xhtml):

> **Attribute Protocol (ATT)**
> Bluetooth Low Energy brought two core specifications and every Low Energy profile is supposed to use them. Attribute Protocol and Generic Attribute Profile.
> 
> Attribute Protocol is a low-level layer that defines how to transfer data. It identifies the device discovery, reading and writing attributes on a fellow device. 
> 
> On the other hand, Generic Attribute Profile is built on the top of ATT to give high-level services to the manufacturer implementing LE. These services are basically used to manage the data transfer process in a more systematic way. For example, GATT defines if a device's role is going to be Server or Client.

We now know that **ATT** is used in **Bluetooth Low Energy (BLE)**, and used to transfer data. To learn more in-depth about the **ATT** protocol, check out this [this post](https://stackoverflow.com/questions/30034541/low-level-bluetooth-packet-analysis) on StackOverflow. As we want to extract data, we filter out the other protocols using `btatt`in the Wireshark display filter:

![](https://i.imgur.com/fxw9JZQ.jpg)

We notice that data is transfered through the `Value` field in packets. Also, by scrolling through the packets, we notice only two specific `Handle` values contain relevant data:
* `Handle 0x008f` contains text messages
* `Handle 0x008c` contains bytes of an `ELF executable`

Packets with these two `Handle` values, can be filtered using these display filters:
* `btatt.handle==0x008f`
* `btatt.handle==0x008c`

Also, only packets with a length above 14 contain data. Hence, we add the following to our display filter:
* `frame.len>14`

By combining the two, we view only relevant packets with data, such as:
```
btatt.handle==0x008c && frame.len>14
```
_Note: Check out [Wireshark's display filter expressions](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html) if unfamilar_

![](https://i.imgur.com/f6Zieoi.jpg)

## Extracting data bytes
Now that we know how to filter the relevant packets, we need to extract the data bytes from these packets. This can be done using `tshark`. Using `tshark -h`, we find these relevant options:  

| Option and Format                                          | Explanation                                         |
|------------------------------------------------------------|-----------------------------------------------------|
| `-r <infile>, --read-file <infile>`                        | set the filename to read from (or '-' for stdin)    |
| `-Y <display filter>, --display-filter <display filter>`   | packet display filter in Wireshark display filter   |
| `-T pdml|ps|psml|json|jsonraw|ek|tabs|text|fields`         | format of text output                               |
| `-e <field>`                                               | field to print if -Tfields selected (e.g. tcp.port) |

Thus, data can be extracted using the command:
```
tshark -r iot-challenge-3.pcap -T -Y "frame.len>14 && btatt.handle==0x008f" -e "btatt.value"
```

The output from `tshark` can be piped into a file using the `>` operator. I used the following python code to convert the data bytes into their corresponding files:

```python
# To parse messages
raw_data = open('messages_raw', 'r')
lines = raw_data.readlines()

messages = []
for line in lines:
    message = line[:-1].decode('hex')
    messages.append(message + '\n')

message_file = open('messages.txt', 'w')
message_file.writelines(messages)
```

```python
# To parse data into ELF
import binascii

raw_data = open('data', 'r')
lines = raw_data.readlines()

elf = open('elf_file', 'wb')

messages = []
for line in lines:
    byte_string = binascii.unhexlify(line[:-1])
    elf.write(byte_string)
```

We end up with the following messages, which do not seem to be important:
```
Bro: Dude did u ate my chips
(Too cool 4 u) TK: Emma owes me $36 for the dinner
Boss: I will not be in the office
Boss: Can u help me check smth on my com real quick
Boss: Check my calendar for today
Boss: It's on my desk
(Too cool 4 u) Emma: $36??
(Too cool 4 u) TK: Well $26 for the steak $10 for the drinks
(Too cool 4 u): Max: Cool..
Boss: Any updates?
Boss: Zzzzz
Boss: What is taking so long?!
(Too cool 4 u) Brad: Last night was LITTTT
Mom: I made dinner
Boss: U got to be kidding me
Boss: Password I gave is right
(Too cool 4 u) Meg: Thanks for the dinner outing!
Boss: Do u even know how to use a com??!
John: He's onto you again huh?
Tammy: U free tonight?
(Too cool 4 u) Don: Dinner anyone?
Tammy: Urgent text me ASAP
Boss: WELL??
(Too cool 4 u) Brad: Sure where to?
(Too cool 4 u) Brad: PM me
```

We also end up with the following executable, which can be identified using `file <ELF_FILE>`:
```
ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-armhf.so.3, for GNU/Linux 2.6.32, BuildID[sha1]=d73f4011dd87812b66a3128e7f0cd1dcd813f543, not stripped
```

## Reversing: Static Analysis
Using a decompiler, such as **Ghidra** or **IDA**, we can see the program logic. Below is a cleaned-up version of the decompilation:
```c
int main(int argc, const char **argv, const char **envp) {
  printf("Secret?");
  fgets(&buf, 10, stdin);
  if ( strlen(&buf) != 8 ) {
    puts("Sorry wrong secret! An alert has been sent!");
    exit(0);
  }
  
  i = 0;
  buf_len = strlen(&buf);
  if ( buf[0] == magic(105 - buf_len) ) ++i;
  if ( buf[1] == magic(105 ^ 0x27) ) ++i;
  if ( buf[2] == magic(105 + 11) ) ++i;
  if ( buf[3] == magic(2 * buf[1] - 51) ) ++i;
  if ( buf[4] == magic(0x42) ) ++i;
  if ( buf[5] == magic((8 * (i - 1)) | 1) ) ++i;

  temp = buf[3] + buf[4] + buf[5];
  c = (temp ^ (buf[3] + buf[5] + 66)) + 101;
  if ( buf[6] == magic(c) ) ++i;

  if ( i == 7 )
    puts("Authorised!");
  else
    puts("Sorry wrong secret! An alert has been sent!");
}
```

We see that the program takes in input of 10 bytes using `fgets()`:
```c
fgets(&buf, 10, stdin);
```

The program checks if the length of the input is 8 bytes long, and terminates with a wrong message if it isn't:  
_Note: The correct input actually has a length of 7 as fgets() appends a \n character to the end of input_
```c
if ( strlen(&buf) != 8 ) {
    puts("Sorry wrong secret! An alert has been sent!");
    exit(0);
}
```

The program then compares each byte to a value generated using a `magic()` function, and increments `i` by 1 if true.
```c
i=0;
buf_len = strlen(&buf);
if ( buf[0] == magic(105 - buf_len) ) ++i;
if ( buf[1] == magic(105 ^ 0x27) ) ++i;
if ( buf[2] == magic(105 + 11) ) ++i;
if ( buf[3] == magic(2 * buf[1] - 51) ) ++i;
if ( buf[4] == magic(0x42) ) ++i;
if ( buf[5] == magic((8 * (i - 1)) | 1) ) ++i;

temp = buf[3] + buf[4] + buf[5];
c = (temp ^ (buf[3] + buf[5] + 66)) + 101;
if ( buf[6] == magic(c) ) ++i;
```

At the end, it checks if `i` equals 7, and prints a success or fail message accordingly:
```c
if ( i == 7 )
    puts("Authorised!");
else
    puts("Sorry wrong secret! An alert has been sent!");
```

It would be possible to obtain the flag purely by static analysis of the `magic()` function. However:

* `magic()` actually contains four other nested functions, making it tedious to reverse.
* **I am lazy.**

Thus, we move on to dynamic analysis.

## Reversing: Dynamic Analysis
### Setup
To setup Linux to run arm binaries, check out [this post](https://ownyourbits.com/2018/06/13/transparently-running-binaries-from-any-architecture-in-linux-with-qemu-and-binfmt_misc/).

To perform dynamic analysis, we will debug the binary with `gdb`. To setup:
* Install **gdb-multiarch** with `sudo apt-get install gdb-multiarch`
* In one terminal window, run the binary with `qemu-arm -g <PORT> ./<ELF_FILE>`. For example: `qemu-arm -g 1234 ./elf_file`
* In another terminal window, run:
	* `gdb-multiarch <ELF_FILE>`
	* `target remote HOST:PORT`, for example: `target remote localhost:1234`
	* `c`, to continue execution of the program

This allows us to run the binary normally, and pause execution in **gdb** using `<ctrl-c>` to debug.

### Obtaining the flag
As mentioned before, the binary compares each byte to a value returned by `magic()`. We notice that:
* The bytes are checked from index 0 to 6
* Following bytes do not affect the check of previous bytes. This means, that `buf[6]` will not affect the value returned by `magic()` when checking `buf[3]`, or any other previous bytes.

This means we can obtain the correct character at any position if we know the correct characters in previous positions. As such, we do the following:
* Set a breakpoint in `magic()` to find its return value
* Run the binary until breakpoint is hit
* Print the return value of `magic()`
* Append this value to the input
* Repeat until we get the entire password

_Before diving into gdb, remember that the aim is to obtain the return values of magic()_  
We use the `disas` command to obtain the disassembly of the `magic()` function:
```
(gdb) disas magic
Dump of assembler code for function magic:
   0x000107c8 <+0>:     push    {r11, lr}
   0x000107cc <+4>:     add     r11, sp, #4
   0x000107d0 <+8>:     sub     sp, sp, #8
   0x000107d4 <+12>:    mov     r3, r0
   0x000107d8 <+16>:    strb    r3, [r11, #-5]
   0x000107dc <+20>:    ldrb    r3, [r11, #-5]
   0x000107e0 <+24>:    mov     r0, r3
   0x000107e4 <+28>:    bl      0x10820 <magic2>
   0x000107e8 <+32>:    mov     r3, r0
   0x000107ec <+36>:    strb    r3, [r11, #-5]
   0x000107f0 <+40>:    mov     r0, #3
   0x000107f4 <+44>:    mov     r1, #2
   0x000107f8 <+48>:    bl      0x10980 <min>
   0x000107fc <+52>:    mov     r3, r0
   0x00010800 <+56>:    uxtb    r2, r3
   0x00010804 <+60>:    ldrb    r3, [r11, #-5]
   0x00010808 <+64>:    add     r3, r2, r3
   0x0001080c <+68>:    strb    r3, [r11, #-5]
   0x00010810 <+72>:    ldrb    r3, [r11, #-5]
   0x00010814 <+76>:    mov     r0, r3
   0x00010818 <+80>:    sub     sp, r11, #4
   0x0001081c <+84>:    pop     {r11, pc}
End of assembler dump.
```
In `x86 ARM` architecture, return values are stored in registers (`r0` in this case). We set a breakpoint right before `magic()` ends, with the following:
```
(gdb) b *magic+84
Breakpoint 1 at 0x1081c
```
As we want to print the value stored in `r0` as a character everytime the breakpoint is hit, we can use the `define hook-stop` command:
```
(gdb) define hook-stop
Type commands for definition of "hook-stop".
End with a line saying just "end".
>print (char) $r0
>end
```

We then continue execution three times until the character printed is no longer correct. 
```
(gdb) c
Continuing.
$8 = 97 'a'

Breakpoint 1, 0x0001081c in magic ()
(gdb) c
Continuing.
$9 = 78 'N'

Breakpoint 1, 0x0001081c in magic ()
(gdb) c
Continuing.
$10 = 116 't'

(gdb) c
Continuing.
$11 = 143 '\217'

Breakpoint 1, 0x0001081c in magic ()
```

This is because the return value of `magic()` now depends on previous characters, as seen in this code:
```c
if ( buf[3] == magic(2 * buf[1] - 51) ) ++i;
```

Thus, we restart execution and enter `aNtaaaa` as input:  
_In gdb terminal window_
```
(gdb) kill
Kill the program being debugged? (y or n) y
[Inferior 1 (process 1) killed]
(gdb) target remote localhost:1234
Remote debugging using localhost:1234
(gdb) c
```

_In other terminal window_
```
 $ qemu-arm -g 1234 ./elf_file
 Secret?aNtaaaa
 ```
 
 This allows us to obtain more correct characters in **gdb**:
 ```
 (gdb) c
Continuing.
$13 = 97 'a'

Breakpoint 1, 0x0001081c in magic ()
(gdb) c
Continuing.
$14 = 78 'N'

Breakpoint 1, 0x0001081c in magic ()
(gdb)
Continuing.
$15 = 116 't'

Breakpoint 1, 0x0001081c in magic ()
(gdb)
Continuing.
$16 = 105 'i'

Breakpoint 1, 0x0001081c in magic ()
(gdb)
Continuing.
$17 = 66 'B'

Breakpoint 1, 0x0001081c in magic ()
(gdb)
Continuing.
$18 = 17 '\021'

Breakpoint 1, 0x0001081c in magic ()
```

We repeat the process, which gives us the entire flag before the program terminates:
```bash 
(gdb) c
Continuing.
$21 = 97 'a'

Breakpoint 1, 0x0001081c in magic ()
(gdb) c
Continuing.
$22 = 78 'N'

Breakpoint 1, 0x0001081c in magic ()
(gdb)
Continuing.
$23 = 116 't'

Breakpoint 1, 0x0001081c in magic ()
(gdb)
Continuing.
$24 = 105 'i'

Breakpoint 1, 0x0001081c in magic ()
(gdb)
Continuing.
$25 = 66 'B'

Breakpoint 1, 0x0001081c in magic ()
(gdb)
Continuing.
$26 = 33 '!'

Breakpoint 1, 0x0001081c in magic ()
(gdb)
Continuing.
$27 = 101 'e'

Breakpoint 1, 0x0001081c in magic ()
(gdb)
Continuing.
[Inferior 1 (process 1) exited normally]
Error while running hook_stop:
No registers
```

The above shows us the secret pass is `aNtiB!e`. Let us check:
```bash 
$ qemu-arm elf_file
Secret?aNtiB!e
Authorised!
```

It is correct, hence the flag is `govtech-csg{aNtiB!e}`

**Flag:** `govtech-csg{aNtiB!e}`