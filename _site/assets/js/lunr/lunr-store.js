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
        "title": "Substitution Cipher Decryption with Genetic Algorithms",
        "excerpt":"This project implements Genetic Algorithms to decrypt Monoalphabetic Substitution Ciphers using frequency analysis. Project Files Demo The plaintext used is from the opening line of The Great Gatsby: 'In my younger and more vulnerable years my father gave me some advice that I've been turning over in my mind ever...","categories": [],
        "tags": ["Genetic Algorithms","Substitution Cipher","Projects"],
        "url": "http://localhost:4000/GA-Substitution-Cipher/",
        "teaser":null},{
        "title": "Cyberthon 2020",
        "excerpt":"Team Name: acsi-1  Position: 3  Score: 6856  Other honors: Winner of Data Science Category     ","categories": [],
        "tags": ["Cyberthon","CTF"],
        "url": "http://localhost:4000/Cyberthon-2020/",
        "teaser":null},{
        "title": "A to Z of COViD! [1986]",
        "excerpt":"Category: Mobile Challenge Description Over here, members learn all about COViD, and COViD wants to enlighten everyone about the organisation. Go on, read them all! Flag Format: govtech-csg{alphanumeric-and-special-characters-string Initial Analysis This challenge to the activity launched by CovidInfoActivity.java. Launching the activity in an emulator, the following screen is displayed: The...","categories": [],
        "tags": ["Stack 2020","Mobile"],
        "url": "http://localhost:4000/A-to-Z-of-COViD!/",
        "teaser":null},{
        "title": "An invitation [981]",
        "excerpt":"Category: Web Challenge Description We want you to be a member of the Cyber Defense Group! Your invitation has been encoded to avoid being detected by COViD’s sensors. Decipher the invitation and join in the fight! Starting off Looking at index.html, we open it in the browser, but nothing seems...","categories": [],
        "tags": ["Stack 2020","Reversing"],
        "url": "http://localhost:4000/An-invitation/",
        "teaser":null},{
        "title": "COVID's Communication Technology! [984]",
        "excerpt":"Category: Internet of Things (IoT) Challenge Description We heard a rumor that COVID was leveraging that smart city’s ‘light’ technology for communication. Find out in detail on the technology and what is being transmitted. Initial Analysis We are given a .logicdata file. After some research, we find that it is...","categories": [],
        "tags": ["Stack 2020","IoT"],
        "url": "http://localhost:4000/COVID's-Communication-Technology!/",
        "teaser":null},{
        "title": "Can COViD steal Bob's idea? [960]",
        "excerpt":"Category: Cryptography Challenge Description Bob wants Alice to help him design the stream cipher’s keystream generator base on his rough idea. Can COViD steal Bob’s “protected” idea? Method To handle the .pcapng file, we open it in WireShark. We can extract the following text: p = 298161833288328455288826827978944092433 g = 216590906870332474191827756801961881648...","categories": [],
        "tags": ["Stack 2020","Cryptography"],
        "url": "http://localhost:4000/Can-COViD-steal-Bob's-idea/",
        "teaser":null},{
        "title": "Can you trick OrgX into giving away their credentials? [2000]",
        "excerpt":"Category: Social Engineering Challenge Description With the information gathered, figure out who has access to the key and contact the person Finding the Target Since we need to contact a person, it’s most likely a phone number or email. A quick note on sending emails during CTFs: In the wise...","categories": [],
        "tags": ["Stack 2020","Social Engineering"],
        "url": "http://localhost:4000/Can-you-trick-OrgX-into-giving-away-their-credentials/",
        "teaser":null},{
        "title": "Find the leaking bucket! [978]",
        "excerpt":"Category: Cloud Challenge Description It was made known to us that agents of COViD are exfiltrating data to a hidden S3 bucket in AWS! We do not know the bucket name! One tip from our experienced officers is that bucket naming often uses common words related to the company’s business....","categories": [],
        "tags": ["Stack 2020","Cloud"],
        "url": "http://localhost:4000/Find-the-leaking-bucket!/",
        "teaser":null},{
        "title": "Hunt him down! [970]",
        "excerpt":"Category: Open Source Intelligence (OSINT) Challenge Description After solving the past two incidents, COViD sent a death threat via email today. Can you help us investigate the origins of the email and identify the suspect that is working for COViD? We will need as much information as possible so that...","categories": [],
        "tags": ["Stack 2020","OSINT"],
        "url": "http://localhost:4000/Hunt-him-down!/",
        "teaser":null},{
        "title": "I smell updates! [1986]",
        "excerpt":"Category: Internet of Things (IoT) Challenge Description Agent 47, we were able to retrieve the enemy’s security log from our QA technician’s file! It has come to our attention that the technology used is a 2.4 GHz wireless transmission protocol. We need your expertise to analyse the traffic and identify...","categories": [],
        "tags": ["Stack 2020","IoT"],
        "url": "http://localhost:4000/I-smell-updates!/",
        "teaser":null},{
        "title": "Only time will tell! [691]",
        "excerpt":"Category: Open Source Intelligence (OSINT) Challenge Description This picture was taken sent to us! It seems like a bomb threat! Are you able to tell where and when this photo was taken? This will help the investigating officers to narrow down their search! All we can tell is that it’s...","categories": [],
        "tags": ["Stack 2020","OSINT"],
        "url": "http://localhost:4000/Only-time-will-tell!/",
        "teaser":null},{
        "title": "Sounds of freedom! [750]",
        "excerpt":"Category: Open Source Intelligence (OSINT) Challenge Description In a recent raid on a suspected COViD hideout, we found this video in a thumbdrive on-site. We are not sure what this video signifies but we suspect COViD’s henchmen might be surveying a potential target site for a biological bomb. We believe...","categories": [],
        "tags": ["Stack 2020","OSINT"],
        "url": "http://localhost:4000/Sounds-of-freedom!/",
        "teaser":null},{
        "title": "Stack the Flags 2020",
        "excerpt":"Name: ItzyBitzySpider Position: 3 Score: 37754 Participated in this CTF with my regular teammates in the JC category, @jloh02, @OceanKoh, @NyxTo. Not all the writeups below are by me, so credits to them. Challenge Writeups Binary Exploitation Reversing An invitation [981] Web Unlock Me [905] Cryptography Can COViD steal Bob’s...","categories": [],
        "tags": ["Stack 2020","CTF"],
        "url": "http://localhost:4000/Stack-the-Flags-2020/",
        "teaser":null},{
        "title": "Unlock Me [905]",
        "excerpt":"Category: Web Opening the webpage we try to login with the credentials given to us user: minion, password: banana. This however returns a message saying that only admins are allowed into HQ. Using a proxy like ZAP allows us to inspect the request further. We notice that the login process...","categories": [],
        "tags": ["Stack 2020","Web"],
        "url": "http://localhost:4000/Unlock-Me/",
        "teaser":null},{
        "title": "Voices in the head [1692]",
        "excerpt":"Category: Forensics Challenge Description We found a voice recording in one of the forensic images but we have no clue what’s the voice recording about. Are you able to help? Initial Analysis We are given a WAV audio file. Sometimes, the spectrogram contains text as seen from previous CTF experience....","categories": [],
        "tags": ["Stack 2020","Forensics"],
        "url": "http://localhost:4000/Voices-in-the-head/",
        "teaser":null},{
        "title": "Walking down a colourful memory lane [992]",
        "excerpt":"Category: Forensics Challenge Description We are trying to find out how did our machine get infected. What did the user do? Memory Analysis We are given a .mem file (Memory dump). We can use the premier tool for memory forensics volatility. In my 2 weeks of memory forensics experience, I...","categories": [],
        "tags": ["Stack 2020","Forensics"],
        "url": "http://localhost:4000/Walking-down-a-colourful-memory-lane/",
        "teaser":null},{
        "title": "Who are the possible kidnappers? [1990]",
        "excerpt":"Category: Open Source Intelligence (OSINT) Challenge Description Perform OSINT to gather information on the organisation’s online presence. Start by identifying a related employee and obtain more information. Information are often posted online to build the organization’s or the individual’s online presence (i.e. blog post). Flag format is the name of...","categories": [],
        "tags": ["Stack 2020","OSINT"],
        "url": "http://localhost:4000/Who-are-the-possible-kidnappers/",
        "teaser":null},{
        "title": "What is he working on? Some high value project? [790]",
        "excerpt":"Category: Open Source Intelligence (OSINT) Challenge Description The lead Smart Nation engineer is missing! He has not responded to our calls for 3 days and is suspected to be kidnapped! Can you find out some of the projects he has been working on? Perhaps this will give us some insights...","categories": [],
        "tags": ["Stack 2020","OSINT"],
        "url": "http://localhost:4000/Working-on/",
        "teaser":null}]
