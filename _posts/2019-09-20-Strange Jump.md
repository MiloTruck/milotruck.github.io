---
title: "Strange Jump[250]"
tags: [Timisoara CTF, Reversing]
excerpt: "Reversing"
layout: single
classes: wide
--- 

**Category:** Reversing

> This program likes to jump!

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/Timisoara%20CTF%202019%20Qualification%20Round/Reversing/Strange%20Jump%20%5B250%5D){: .btn .btn--primary}

## Write-up
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

**Flag:** TIMCTF{deC3pt1ve_ExceP0ti0n_h4ndLer}