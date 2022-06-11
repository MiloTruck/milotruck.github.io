---
title: "Grey Cat The Flag Qualifiers 2022"
date: 2022-06-11
categories: CTF
--- 

This CTF was the qualifying round for Grey Cat The Flag 2022, hosted by the National University of Singapore (NUS). Under the name **ItzyBitzySpider**, I participated with my regular teammates [@OceanKoh](https://blog.puddle.sg/) and [@NyxTo](https://github.com/Nyxto). We managed to place 10th, which was just enough to qualify for the finals.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/Grey Cat The Flag Qualifiers 2022/Scoreboard.JPG)

# Writeups  

## Runtime Environment 1

> GO and try to solve this basic challenge.
> 
> FAQ: If you found the input leading to the challenge.txt you are on the right track

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/Grey%20Cat%20The%20Flag%20Qualifiers%202022/Runtime%20Environment%201){: .btn .btn--primary}

**Solution**

Upon unzipping `gogogo.tar.gz`, we are provided with a challenge binary and a text file.
```bash
$ tar xvzf gogogo.tar.gz
binary
challenge.txt
```

`binary` is a 64-bit ELF, while `challenge.txt` seems to contain some encoded text, which we can assume is output from `binary`:
```bash
$ file binary
binary: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=OHBJFJh5S4MEkda8Q683/cMydJq6y9QbVjBCjK1KP/8R1f9ddSl9EfpM8KP2Dy/3G9-Ju3BW7WUsgoGNyvl, not stripped

$ cat challenge.txt
GvVf+fHWz1tlOkHXUk3kz3bqh4UcFFwgDJmUDWxdDTTGzklgIJ+fXfHUh739+BUEbrmMzGoQOyDIFIz4GvTw+j--
```

When provided with a ELF binary for reversing challenges, I like to run it a few times to get a general idea of what it does:
```bash
$ ./binary
AAAAAAAA
VbTaVbTaVbJ-
$ ./binary
AAA
VbTa
$ ./binary
BBBB
V7mRVj--
```
From the output, we can observe a few things:
1. `binary` seems to take in plaintext as input and output an encoded text
2. The encoded output looks *oddly similar* to Base64 encoding

Especially since the `binary` is written in `go`, which might be harder to reverse, I thought that there was no harm in reading up on Base64 before attempting to reverse the binary. From [this website](http://www.herongyang.com/Encoding/Base64-Encoding-Algorithm.html), we can see that the Base64 algorithm is as follows:

> 1. Divide the input byte stream into blocks of 3 bytes.
> 
> 2. Divide 24 bits of each 3-byte block into 4 groups of 6 bits.
> 
> 3. Map each group of 6 bits to 1 printable character, based on the 6-bit value using the Base64 character set map.
> 
> 4. If the last 3-byte block has only 1 byte of input data, pad 2 bytes of zeros `\x00\x00`. After encoding it as a normal block, overwrite the last 2 characters with 2 equal signs `==`, so the decoding process knows 2 bytes of zero were padded.
> 
> 5. If the last 3-byte block has only 2 bytes of input data, pad 1 byte of zero `\x00`. After encoding it as a normal block, overwrite the last 1 character with 1 equal sign `=`, so the decoding process knows 1 byte of zero was padded.

Essentially, the input is divided into blocks of 3 characters and converted to binary (24 bits). Then, every 6 bits is converted into a new Base64 character, resulting in 4 bytes of encrypted text. If the last block has less than 3 characters, it is encoded to Base64 and then padded with `=` to become 4 bytes.

Now that we have a rough understanding of how Base64 works, we can attempt to reverse the binary. The `main_main()` function of the decompiled code is shown:
```c
void __cdecl main_main()
{
  v9 = runtime_newobject(&unk_4AB9C0);
  v11[0] = &unk_4A86A0;
  v11[1] = v9;
  v1 = fmt_Fscanln(&go_itab__os_File_io_Reader, os_Stdin, v11);
  enc_len = 4 * ((((((v9[1] + 2) * 0xAAAAAAAAAAAAAAABLL) >> 64) + v9[1] + 2) >> 1) - ((v9[1] + 2) >> 63));
  runtime_makeslice(qword_4ABB00, enc_len, enc_len);
  v8 = v1;
  runtime_stringtoslicebyte(v7, *v9, v9[1]);
  main_Encode(v8, enc_len, enc_len, v1, 1uLL);
  runtime_slicebytetostring(0LL, v4, v5);
  runtime_convTstring(v2, v3);
  v10[0] = &unk_4AB9C0;
  v10[1] = v0;
  fmt_Fprintln(&go_itab__os_File_io_Writer, os_Stdout, v10, 1LL, 1LL);
}
```

Although the decompilation seems quite messy, we can infer that the binary:
1. Reads in user input using `fmt_Fscanln()`
2. Passes the input to `main_Encode()` for encryption
3. Outputs the encrypted text using `fmt_Fprintln()`

Thus, we look at the `main_Encode()` function to figure out how input is encrypted:
```c
// Note: I have cleaned up the code and removed error checking to make the decompilation more readeable
__int64 __usercall main_Encode@<rax>(
    char *buf,
    unsigned __int64 enc_len,
    __int64 ret,
    char *input,
    unsigned __int64 input_len)
{
  // Copy the string into key, which will be used for the character set
  // NOTE: Notice how key has 64 characters, which suggests this is a Base64 character set
  qmemcpy(key, "NaRvJT1B/m6AOXL9VDFIbUGkC+sSnzh5jxQ273d4lHPg0wcEpYqruWyfZoM8itKe", sizeof(key));

  // Declare indexes for input and buf
  // input - input buffer
  // buf - buffer that contains encoded text
  input_i = 0LL;
  buf_i = 0LL;

  // Loop while index of input is less than length of input rounded down to nearest 3
  while ( input_i < 3 * (input_len / 3) ) {
    // Convert 3 bytes from input into binary      
    binary = (input[input_i] << 16) | (input[input_i + 1] << 8) | input[input_i + 2];

    // Convert every 6 bits into an integer, and use it as an index to fetch a character in key
    // Then, store the character in buf as the encoded text
    buf[buf_i] = key[(binary >> 18) & 0x3F];
    buf[buf_i + 1] = key[(binary >> 12) & 0x3F];
    buf[buf_i + 2] = key[(binary >> 6) & 0x3F];
    buf[buf_i + 3] = key[binary & 0x3F];

    // Increment input and buf indexes
    input_i += 3LL;
    buf_i += 4LL;
  }
  
  // If there is no input left to encode, return the encoded output
  if ( input_len == input_i )
    return ret;

  // Get the remaining length of input that has not been encoded
  remainder = input_len - input_i;

  if ( remainder == 2 ) {
    // If 2 bytes remaining, convert the last 2 characters into binary
    binary = (in[input_i] << 16) | (in[input_i + 1] << 8);
  } else {
    // If 1 byte remaining, convert the last character into binary
    binary = in[input_i] << 16;
  }
  
  // Convert every 6 bits into an integer, and use it as an index to fetch a character in key
  // Then, store the character in buf as the encoded text 
  buf[buf_i] = key[(binary >> 18) & 0x3F];
  buf[buf_i + 1] = key[(binary >> 12) & 0x3F];
  

  if ( remainder == 1 ) {
    // If 1 byte remaining, append "--" to the encoded text
    buf[buf_i + 2] = '-';
    buf[buf_i + 3] = '-';
  } else if ( remainder == 2 ) {
    // If 2 bytes remaining, convert the last 6 bits and fetch another character from key
    // Store it in the 2nd last position in buf
    buf[buf_i + 2] = key[(binary >> 6) & 0x3F];

    // Append "-" to the last position in buf
    buf[buf_i + 3] = '-';
  }
  
  // Return the encoded output
  return ret;
}
```

As seen from the decompiled code, `main_Encode()` is very similar to Base64, with the only differences being:
* `NaRvJT1B/m6AOXL9VDFIbUGkC+sSnzh5jxQ273d4lHPg0wcEpYqruWyfZoM8itKe` is used as the character set instead of the standard `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
* `-` is used for padding instead of `=`

With this knowledge, we can decrypt the encoded text in `challenge.txt` using [CyberChef with a custom Base64 character set](https://gchq.github.io/CyberChef/#recipe=From_Base64('NaRvJT1B/m6AOXL9VDFIbUGkC%2BsSnzh5jxQ273d4lHPg0wcEpYqruWyfZoM8itKe',true,false)&input=R3ZWZitmSFd6MXRsT2tIWFVrM2t6M2JxaDRVY0ZGd2dESm1VRFd4ZERUVEd6a2xnSUorZlhmSFVoNzM5K0JVRWJybU16R29RT3lESUZJejRHdlR3K2otLQ). After 4 rounds of decryption, the flag is given as output.

**Flag:** `grey{B4s3d_G0Ph3r_r333333}`

## Memory Game (Part 2)

> Can you finish MASTER difficulty in 20 seconds? If you can, the flag will be given to you through logcat with the tag FLAG.
> 
> Hint:
> [Frida](https://www.youtube.com/watch?v=iMNs8YAy6pk&ab_channel=sambal0x) is nice.

[Challenge Files](https://github.com/MiloTruck/CTF-Archive/tree/master/Grey%20Cat%20The%20Flag%20Qualifiers%202022/Memory%20Game%20(Part%202)){: .btn .btn--primary}

**Solution**

We are provided with `memory-game.apk`, which is a memory card game with multiple difficulty levels, as shown below:

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/Grey Cat The Flag Qualifiers 2022/Memory Game (Part 2) - 1.JPG) ![alt]({{ site.url }}{{ site.baseurl }}/assets/images/Grey Cat The Flag Qualifiers 2022/Memory Game (Part 2) - 2.JPG)

From the challenge description, we know that to get the flag through `logcat`, that the goal is to complete the *Master* difficulty within 20 seconds. Since this is impossible, we will have to find some way to bypass actually winning the game.

When looking through the decompilation with [JEB Decompiler](https://www.pnfsoftware.com/), this part of the code in `Engine` seems to handle printing of the flag:
```java
int remainingCards = this.mToFlip - 2;
this.mToFlip = remainingCards;
if(remainingCards == 0) {
    int usedTime = (int)(Clock.getInstance().getPassedTime() / 1000L);
    Clock.getInstance();
    int timeLimit = this.mPlayingGame.boardConfiguration.time;
    GameState v3 = new GameState();
    this.mPlayingGame.gameState = v3;
    v3.remainedSeconds = timeLimit - usedTime;
    v3.passedSeconds = usedTime;
    if(usedTime <= timeLimit / 2) {
        v3.achievedStars = 3;
    }
    else if(usedTime <= timeLimit - timeLimit / 5) {
        v3.achievedStars = 2;
    }
    else if(usedTime < timeLimit) {
        v3.achievedStars = 1;
    }
    else {
        v3.achievedStars = 0;
    }

    v3.achievedScore = this.mPlayingGame.boardConfiguration.difficulty * v3.remainedSeconds * this.mPlayingGame.theme.id;
    Memory.save(this.mPlayingGame.theme.id, this.mPlayingGame.boardConfiguration.difficulty, v3.achievedStars);
    Memory.saveTime(this.mPlayingGame.theme.id, this.mPlayingGame.boardConfiguration.difficulty, v3.passedSeconds);
    Shared.eventBus.notify(new GameWonEvent(v3), 1200L);
    if(this.mPlayingGame.boardConfiguration.difficulty == 6 && usedTime < timeLimit) {
        SecretKeySpec v12_3 = null;
        try {
            v2_1 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        } catch(NoSuchAlgorithmException | NoSuchPaddingException v3_1) {
            v2_1 = null;
            goto label_111;
        }

        try {
            v3_2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            goto label_115;
        } catch(NoSuchAlgorithmException v3_1) {} catch(NoSuchPaddingException v3_1) {}

    label_111:
        v3_1.printStackTrace();
        v3_2 = null;
    label_115:
        Rnd.reSeed();
        byte[] v6 = new byte[16];
        int v7;
        for(v7 = 0; v7 < 16; ++v7) {
            v6[v7] = (byte)Rnd.get(0x100);
        }

        PBEKeySpec v7_1 = new PBEKeySpec("1.01.001007".toCharArray(), v6, 0x10000, 0x100);
        try {
            v6_1 = new SecretKeySpec(v2_1.generateSecret(v7_1).getEncoded(), "AES");
        } catch(InvalidKeySpecException v2_2) {
            v2_2.printStackTrace();
            goto label_142;
        }

        v12_3 = v6_1;
    label_142:
        byte[] v2_3 = new byte[16];
        int v6_2;
        for(v6_2 = 0; v6_2 < 16; ++v6_2) {
            v2_3[v6_2] = (byte)Rnd.get(0x100);
        }

        IvParameterSpec v4 = new IvParameterSpec(v2_3);
        try {
            v3_2.init(2, v12_3, v4);
        } catch(InvalidAlgorithmParameterException v12_5) {
            v12_5.printStackTrace();
        } catch(InvalidKeyException v12_4) {
            v12_4.printStackTrace();
        }

        try {
            Log.i("FLAG", new String(v3_2.doFinal(Base64.decode("diDrBf4+uZMtDV+0k/3BCGM4xyTpEyGEuUFYegIaSjQyQcgfIfZRbvGQ9hHMqnuflNCKv4HW/NXq93j4QqLc/Q==", 0)), StandardCharsets.UTF_8));
        } catch(BadPaddingException v12_7) {
            v12_7.printStackTrace();
        } catch(IllegalBlockSizeException v12_6) {
            v12_6.printStackTrace();
        }
    }
}
```

From the chunk of code above, we can infer that the flag will be printed out should these conditions be met:
1. The number of remaining cards has to be `0`.
```java
int remainingCards = this.mToFlip - 2;
this.mToFlip = remainingCards;
if(remainingCards == 0) {
```
2. The difficulty has to be `6` (which can be assumed as *Master*), and `usedTime` has to be less than `timeLimit`, which is 20 seconds.
```java
int usedTime = (int)(Clock.getInstance().getPassedTime() / 1000L);
int timeLimit = this.mPlayingGame.boardConfiguration.time;
if(this.mPlayingGame.boardConfiguration.difficulty == 6 && usedTime < timeLimit) {
```

Although the hint suggested using **Frida**, I decided to go with patching instead. The idea is to patch `remainingCards == 0` into `remainingCards != 0`. This way, we would win the game whenever we match a pair of cards, as there is no check to ensure there are no cards left to flip.

We use `apktool` to decompile the APK and retrieve the smali code:
```bash
apktool d memory-game.apk
```
In `Engine.smali`, we see that our check corresponds to lines 425 - 433:
```java
iget p1, p0, Lcom/snatik/matches/engine/Engine;->mToFlip:I  // Move Engine->mToFlip into p1

const/4 v0, 0x2  // Set v0 to 0x2

sub-int/2addr p1, v0  // Subtract 0x2 from p1

iput p1, p0, Lcom/snatik/matches/engine/Engine;->mToFlip:I  // This line is irrelevant

if-nez p1, :cond_7  // Jump to :cond_7 if p1 != 0, which is the end of the function
```
We simply flip the check by changing `if-nez` to `if-eqz`:
```java
if-eqz p1, :cond_7  // Jump to :cond_7 if p1 == 0, which is the end of the function
```

We recompile the APK using these commands:
```bash
# Create a keystore
keytool -genkeypair -v -keystore key.keystore -alias example -keyalg RSA -keysize 2048 -validity 10000

# Recompile the apk, the resulting apk should be in memory-game/dist/
apktool b memory-game --use-aapt2 

# Align and sign the apk
zipalign -p -f -v 4 memory-game.apk align.apk
apksigner sign -ks key.keystore --out patched.apk align.apk
```

After installing `patched.apk`, we play the *Master* difficulty and match one pair of cards under 20 seconds. Then, we use `adb` to retrieve the flag from `logcat`:
```bash
$ adb logcat | grep FLAG
06-11 00:00:08.597  4771  4771 I FLAG    : grey{hum4n_m3m0ry_i5_4lw4y5_b3tt3r_th4n_r4nd0m_4cc3ss_m3m0ry}
```

**Flag:** `grey{hum4n_m3m0ry_i5_4lw4y5_b3tt3r_th4n_r4nd0m_4cc3ss_m3m0ry}`