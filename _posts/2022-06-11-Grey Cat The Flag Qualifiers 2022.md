---
title: "Grey Cat The Flag Qualifiers 2022"
date: 2022-06-11
categories: CTF
--- 

This CTF was the qualifying round for Grey Cat The Flag 2022, hosted by the National University of Singapore (NUS). Under the name **ItzyBitzySpider**, I participated with my regular teammates [@OceanKoh](https://blog.puddle.sg/) and [@NyxTo](https://github.com/Nyxto). We managed to place 10th, which was just enough to qualify for the finals.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/Grey Cat The Flag Qualifiers 2022/Scoreboard.JPG)

# Writeups  

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
In `Engine.smali`, we see that our check corresponds to line `425-433`:
```java
iget p1, p0, Lcom/snatik/matches/engine/Engine;->mToFlip:I  # Move Engine->mToFlip into p1

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