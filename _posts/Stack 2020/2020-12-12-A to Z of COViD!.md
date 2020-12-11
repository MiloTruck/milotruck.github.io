---
title: "A to Z of COViD! [1986]"
tags: [Stack 2020, Mobile]
excerpt: "Mobile"
layout: single
classes: wide
--- 

**Category:** Mobile

## Challenge Description
> Over here, members learn all about COViD, and COViD wants to enlighten everyone about the organisation. Go on, read them all!
>
> **Flag Format:** `govtech-csg{alphanumeric-and-special-characters-string`

## Initial Analysis
This challenge to the activity launched by `CovidInfoActivity.java`. Launching the activity in an emulator, the following screen is displayed:

![](https://i.imgur.com/5wY8QST.jpg)

The text field asks for the flag, and upon submission, displays a toast showing `Flag is wrong!`. We now know the flag entered is most probably checked in the `onClick()` function of the submit button.

Using [JADX](https://github.com/skylot/jadx), we can obtain the decompiled Java source code of the apk. As mentioned above, we look for the `onClick()` function in `CovidInfoActivity.java`:
```java
public void onClick(View v) {
    if (this.f2970b.encryptOrNull(((EditText) CovidInfoActivity.this.findViewById(R.id.editText_enteredFlag)).getText().toString()).replaceAll("\\n", BuildConfig.FLAVOR).equalsIgnoreCase(CovidInfoActivity.this.f2969b)) {
        c.a builder = new c.a(CovidInfoActivity.this);
        View view = LayoutInflater.from(CovidInfoActivity.this).inflate(R.layout.custom_alert, (ViewGroup) null);
        ((TextView) view.findViewById(R.id.title)).setText("Congrats!");
        ((TextView) view.findViewById(R.id.alert_detail)).setText("Well done!");
        f.a.a.a.a.e.b.a().d(true);
        builder.h("Proceed", new DialogInterface$OnClickListenerC0073a());
        builder.f("Close", new b());
        builder.k(view);
        builder.l();
        Toast.makeText(CovidInfoActivity.this.getApplicationContext(), "Flag is correct!", 0).show();
        return;
    }
    Toast.makeText(CovidInfoActivity.this.getApplicationContext(), "Flag is wrong!", 0).show();
}
```

Our entered flag is retrieved by the activity using:
```java
CovidInfoActivity.this.findViewById(R.id.editText_enteredFlag)).getText().toString()
```

It is then encrypted using a function named `encryptOrNull()`, before being compared to `CovidInfoActivity.this.f2969b`. By looking at the code in the same file, we see the following relevant code:
```java
public String f2969b = "jeldexs+ktquD8iQ1CAEnHIc+SSPc5TcyirRSIYxA/g=";
```

```java
import se.simbio.encryption.Encryption;

public final Encryption f2970b;
public a(Encryption encryption) {
	this.f2970b = encryption;
}
```

`CovidInfoActivity.this.f2969b` refers to the flag after it is encrypted using  `encryptOrNull()`. We also see that `encryptOrNull()` is a function imported from `Encryption.java`,  another Java file in the apk. Thus, we take a closer look at that file:

```java
public String encryptOrNull(String data) {
    try {
        return encrypt(data);
    } catch (Exception e2) {
        e2.printStackTrace();
        return null;
    }
}
```

The `encryptOrNull()` function calls another function `encrypt()`, which calls more functions and so on... Manually reversing the code through static analysis seems too tedious, thus we look for another method. Scrolling through `Encryption.java`, we see there is a function named `decryptOrNull()`:

```java
public String decryptOrNull(String data) {
    try {
        return decrypt(data);
    } catch (Exception e2) {
        e2.printStackTrace();
        return null;
    }
}
```

Seeing that it is similar to `encryptOrNull()`, it is same to assume this function decrypts data passed into it. As we have the encrypted flag, we just need to find a way to pass it into `decryptOrNull()` and obtain the output.

## Patching the APK
As mentioned above, we want to call `decryptOrNull()` on the encrypted flag to get the flag. This would be possible with [Frida](https://frida.re/), however, I chose to patch the apk as that was more familiar to me.

To obtain the smali code of the apk, we use [ApkTool](https://ibotpeaches.github.io/Apktool/):

```bash
apktool -r d mobile-challenge.apk -o <OUTPUT_DIR>
```

As the relevant code in Java is in `CovidActivity.java`, we look for the smali files related to that. The `OnClick()` function is found in `CovidInfoActivity$a.smali`:
```s
.method public onClick(Landroid/view/View;)V
	.locals 11
    .param p1, "v"    # Landroid/view/View;
	
	...
```

Before diving into patching the code, we identify what we need to do:
* Call `decryptOrNull()` on input entered by us
* Display the output in the apk

Fortunately, smali code is similar to assembly, making it easier for me to identify the code parts I needed to patch.

### Smali Code Analysis

By analyzing the smali code, we see that `encryptOrNull()` is called on our input, and the encrypted input is stored in the variable `v2`:
```s
.line 48
.local v1, "enteredFlagString":Ljava/lang/String;
iget-object v2, p0, Lsg/gov/tech/ctf/mobile/Info/CovidInfoActivity$a;->b:Lse/simbio/encryption/Encryption;

invoke-virtual {v2, v1}, Lse/simbio/encryption/Encryption;->encryptOrNull(Ljava/lang/String;)Ljava/lang/String;

move-result-object v2
```

The encrypted flag is then fetched and stored in `v3`, and compared to our encrypted input in `v2`. The code then jumps to `:cond_0` if they are not equal:

```s
.line 51
iget-object v3, p0, Lsg/gov/tech/ctf/mobile/Info/CovidInfoActivity$a;->c:Lsg/gov/tech/ctf/mobile/Info/CovidInfoActivity;

iget-object v3, v3, Lsg/gov/tech/ctf/mobile/Info/CovidInfoActivity;->b:Ljava/lang/String;

invoke-virtual {v2, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

move-result v3

const/4 v4, 0x0

if-eqz v3, :cond_0
```

We see that `:cond_0` displays `Flag is wrong!` in a toast, hence we do not want to jump to `:cond_0`:
```s
.line 86
:cond_0
iget-object v3, p0, Lsg/gov/tech/ctf/mobile/Info/CovidInfoActivity$a;->c:Lsg/gov/tech/ctf/mobile/Info/CovidInfoActivity;

invoke-virtual {v3}, Landroid/app/Activity;->getApplicationContext()Landroid/content/Context;

move-result-object v3

const-string v5, "Flag is wrong!"

invoke-static {v3, v5, v4}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

move-result-object v3

invoke-virtual {v3}, Landroid/widget/Toast;->show()V
```

Should the code not jump to `:cond_0`, it displays a Congratulations message:
```s
.line 57
.local v7, "details":Landroid/widget/TextView;
const-string v8, "Congrats!"

invoke-virtual {v6, v8}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
```

A more in-depth explanation:
* `equalsIgnoreCase`  is similar to `cmp` assembly. It returns true (1) if both strings are equal, else it returns false (0). The result is then stored in `v3`
* `if-eqz`, similar to `jz` in assembly, jumps to `cond_0` if the value stored in `v3` is equal to 0.
* This allows the app to jump to `cond_0` and display `Flag is wrong!` when the input entered is not equal to the flag.

### Patching Smali Code
With the smali code snippets above, we can actually patch the apk to give us the flag:
* Call `decryptOrNull()` instead of `encryptOrNull()` on input of the  `editText`.
* Jump to `:cond_0` when input is **equal** to the flag, instead of when the flag is wrong. This would allow us to see the congratulations window when we enter a wrong flag instead of a correct one.
* Patch the code to display the output from `decryptOrNull()` instead of `Congrats!` in the congratulations window.

To call `decryptOnNull()` instead, we simply change the function call in `.line 48` :
```s
# From:
invoke-virtual {v2, v1}, Lse/simbio/encryption/Encryption;->encryptOrNull(Ljava/lang/String;)Ljava/lang/String;

# Changed to:
invoke-virtual {v2, v1}, Lse/simbio/encryption/Encryption;->decryptOrNull(Ljava/lang/String;)Ljava/lang/String;
```

In `.line 51`, we find the instruction opposite of `if-eqz`, which is `if-nez`, and make the change:
```s
# From:
if-eqz v3, :cond_0

# Changed to:
if-nez v3, :cond_0
```

The return value of `decryptOrNull()` is stored in `v2`, while the `Congrats!` message is stored in `v8`. We make the appropriate changes to `.line 57`:
```s
# From:
invoke-virtual {v6, v8}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

# Changed to:
invoke-virtual {v6, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
```

### Building patched APK
To build the apk from smali code, we use `apktool`:
```bash
apktool b <OUTPUT_DIR>
```

To sign the apk, we follow the steps in [this post](https://stackoverflow.com/questions/10930331/how-to-sign-an-already-compiled-apk):
* Create a key using:
```bash
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
```

* Sign the apk with:
```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore mobile-challenge.apk alias_name
```

### Getting the Flag
We install the patched APK on an emulator and run it normally. Instead of entering the flag in the Info Page, we key in the encrypted flag:

![](https://i.imgur.com/7yaWgHV.png)

This displays the congratulations window with the flag:

![](https://i.imgur.com/OQ5Bo7x.png)


**Flag:** `govtech-csg{1 L0V3 y0U 3oO0}`