# Overwatch

## Initial Enumeration

Start with nmap, ports then services.

I’ll save both outputs for potential future use:

- `port-scan.txt`
- `svc-scan.txt`

Unfortunately, something is blocking my ping probes.

I’ll test a few workarounds, starting with using `-sS` on a single port: 22, 80, etc.

I’ll use 22 to test.

Cool, the host is definitely up as it returns 22 as filtered.

I’ll test a few other options here to see if we can narrow down the specific blocking mechanism.

| Method | Result |
|----------|----------|
| `-sS` | Success |
| `-Pn` | Success |
| `--disable-arp-ping` | Fail |
| `-T1` | Fail |

`-sS` is the default scan type when using sudo. The connect scan (`-sT`) is much noisier.

`-sT` also narrows down our obfuscation options due to its limited flag compatibility.

Going back to testing for the ports, first I’ll get all available ports using a no-ping stealth scan.

With the list of open ports I can now begin to enumerate the services.

To make things a bit easier I’ll use `ports.txt`, `grep`, `cut`, and `paste` to print the ports in a usable format.

---

## Nmap Findings

### Domain Info

```text
Domain Name: overwatch.htb
Hostname: S200401
OS: Windows
```

### LDAP

Ports 389 and 3268 are open running LDAP.

Port 636 (IANA reservation for LDAPS) and Port 3269 (presumably LDAPS for 3268) are hidden behind TCPWrappers.

The LDAP ports leak the domain name and prove Active Directory presence.

### SMB

Ports:

```text
139
445
```

Findings:

```text
SMB2 Security Mode
3:1:1 - Message signing enabled and required
Clock skew: 6m51s
```

### RDP

Port 3389 (Default RDP) is open.

```text
Target Name: OVERWATCH
NetBIOS Domain Name: OVERWATCH
NetBIOS Computer Name: s200401.overwatch.htb
DNS Tree Name: overwatch.htb
Product Version: 10.0.20348
```

### HTTP

Port 5985 hosts an HTTP server running:

```text
HTTPAPI httpd 2.0
```

### MSSQL

Port 6520 is hosting an MSSQL database.

### RPC

```text
Port 135   - RPC Endpoint Mapper
Port 593   - HTTP RPC Endpoint Mapper
Port 49664 - RPC
Port 49668 - RPC
Port 55053 - RPC
Port 59936 - RPC
Port 63855 - RPC over HTTP 1.0
Port 63856 - RPC
```

### Other Notes

```text
Self-signed SSL certificate for MSSQL
Port 88 = Kerberos
```

### Summary

Windows host named:

```text
S200401
```

Target domain:

```text
overwatch.htb
```

SMB, LDAP, Kerberos, RDP, HTTP, MSSQL, and RPC all have open ports.

Clock skew means that if I want to do anything Kerberos-related later, I’ll likely need to synchronise time first.

---

## SMB Enumeration

From here I’ll start with SMB enumeration using:

- NetExec
- smbclient

The first thing worth checking is anonymous and guest access.

### Anonymous Access

Anonymous access is available but does not have permissions to read any shares.

### Guest Access

Guest access is available and does have read permissions over:

```text
IPC$
software$
```

`IPC$` is a default share.

`software$` is not.

Next I’ll see what `spider_plus` can find.

### Spider Plus Findings

Looking at the `spider_plus` output, the `software$` share contains a mixture of:

- `.dll`
- `.xml`
- `.exe`
- `.exe.config`
- `.pdb`

Initial thoughts:

- XML files may contain sensitive data.
- DLL files may be injectable.
- PDB files often contain useful source references.

Before moving on to `smbclient` I’ll check if any users are leaked through `--rid-brute`.

This returns a massive list of users so I’ll put the output into a file and use some magic to turn it into a functional `users.txt` list using `awk` and `cut`.

I’ll also make a `names.txt` for all the entries that are likely actual employees.

This can be done easily using `grep` to separate the `First.Last` format from the rest.

These files may be helpful later when it comes to identifying credentials.

### smbclient Review

Moving on to `smbclient`, let’s have a look at the custom share and see if there is any information NetExec missed.

It looks much the same as the `spider_plus` output.

Before taking any of the files, I can try uploading an empty file to test write permissions for potential DLL hijacking.

This doesn’t work due to guest account permissions.

(Blue team would have a field day here.)

Next we can have a look at some of the interesting files, grabbing the unique ones and some of the XML files.

---

## File Analysis

### Config File

Looking through the config file, I notice a URL:

```text
http://overwatch.htb:8000/MonitorService
```

Additional findings:

```text
Public key token
EntityFramework version 6.0.0.0
```

### Executable

Looking through what I can see in the executable, nothing stands out.

It seems to be an application for process monitoring.

### PDB

The `.pdb` file contains a bunch of file paths to a C# program.

At this point I took a break because there was definitely something I was missing.

Thinking about it:

I have a Windows executable.

What kind of executable?

A .NET one.

Using `xxd` or `strings` won’t decompile the code, and Ghidra won’t be much help either.

ILSpy is the better option, so I’ll open it up in VSCode using the ILSpy extension.

---

## ILSpy Analysis

Taking a closer look into the executable, there is a `{ }` folder containing the `Program` code.

Inside this there are three functions:

- CheckEdgeHistory
- Main
- Program

### CheckEdgeHistory

This function contains useful hardcoded information:

```text
Server=localhost
Database=SecurityLogs
User Id=sqlsvc
Password=TI0LKcfHzZw1Vv
```

It also tells me the database is:

```text
SQLite Version 3
```

The rest of the code appears to be a logging and cleanup script for Microsoft Edge search history.

Credentials recovered:

```text
sqlsvc:TI0LKcfHzZw1Vv
```

With the credentials for the service account, I can now test the SQL database on port 6520.

---

## MSSQL Enumeration

Using NetExec I can confirm the credentials.

Fortunately, they work.

Then I can use `mssqlclient.py` (thanks Impacket) to connect to the database and start having a look around.

### Databases

There are five databases:

```text
master
tempdb
msdb
overwatch
```

After looking through a good chunk of the data, for now it’s safe to assume they’re all empty.

### Permissions Review

I’ll also look through the enumeration functions of `mssqlclient`.

Findings:

- `sa` is sysadmin but disabled.
- No impersonation privileges.
- `sa` owns all databases except `overwatch`.
- `overwatch` is owned by `sqlsvc`.
- `sqlsvc` does not have permissions for `xp_cmdshell`.

### Linked Servers

`enum_links` shows a linked server named:

```text
SQL07
```

Time to explore this.

After doing a fair amount of research on linked servers, I found a writeup by Slygoo describing a DNS poisoning MITM-style attack called the MSSQL Resurrection Attack.

It leverages:

- `dnstool.py`
- `responder.py`

to add an A record as the MSSQL guest account to the dead `SQL07.overwatch.htb` domain, effectively replacing the callback to SQL07 with one pointed at my local machine.

By setting this trap, Responder can capture authentication credentials.

In this case it worked and I recovered:

```text
sqlmgmt:bIhBbzMMnB82yx
```

### Credential Validation

I’ll use NetExec to test what access this account has.

```text
MSSQL  - Success
SMB    - Success
LDAP   - Success
WinRM  - Success
```

With WinRM authentication I can log in via Evil-WinRM and obtain the user flag.

---

## MonitorService Enumeration

Now with host access, I’ll try to enumerate the service on localhost:8000 discovered earlier.

Trying this with `Invoke-WebRequest` normally doesn’t work.

Using `-UseBasicParsing` does.

Interesting parameters:

```text
?disco
?wsdl
?singleWsdl
```

There are multiple ways to view the output.

I chose to use:

```powershell
(iwr ... -UseBasicParsing).Content
```

and save each response to a file for further analysis on my local machine.

Using Zeep to enumerate the operations and services, `KillProcess` appears to accept input.

Going back to the executable in ILSpy, we can see the `processName` parameter being passed through:

```csharp
String scriptContents =
    "Stop-Process -Name " + processName + " -Force";
```

This looks injectable if I can comment out the remainder of the script, potentially giving command execution.

---

## Status

This investigation is still being documented.

The remaining exploitation and privilege escalation stages will be added in a future update.
