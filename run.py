#!/bin/env python3

import dotenv
import subprocess
from time import sleep
from concurrent.futures import ThreadPoolExecutor

_, _, image_path = [
    entry.split("=")[1].rstrip()
    for entry in open("/home/shafou/.htb-current").readlines()
]


def sync():
    while True:
        subprocess.run(
            f"rsync -a --include='*.png' --exclude='*' {image_path}/ ./assets/img",
            shell=True,
        )
        sleep(5)


def run():
    ENV = (dotenv.get_key(dotenv_path=".env", key_to_get="ENV"),)
    HTB_TOKEN = (dotenv.get_key(dotenv_path=".env", key_to_get="HTB_TOKEN"),)

    subprocess.run(
        f"ENV='{ENV}' HTB_TOKEN='{HTB_TOKEN}' bundle exec jekyll server baseurl='' --drafts --force_polling -w --limit_posts 10",
        shell=True,
    )


with ThreadPoolExecutor() as executor:
    print("Start rsync and jekyll...")
    executor.submit(sync)
    executor.submit(run)
