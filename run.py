#!/bin/env python3

import dotenv
import subprocess
import argparse

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


def run(posts, no_drafts, env):
    cmd = f"ENV='{env}' bundle exec jekyll server baseurl='' --force_polling -w --limit_posts {posts}"

    if env == "prod":
        HTB_TOKEN = dotenv.get_key(dotenv_path=".env", key_to_get="HTB_TOKEN")
        cmd = f"HTB_TOKEN='{HTB_TOKEN}' " + cmd

    if not no_drafts:
        cmd = cmd + " --drafts"

    print(cmd)
    subprocess.run(
        cmd,
        shell=True,
    )


with ThreadPoolExecutor() as executor:
    parser = argparse.ArgumentParser(
        description="Custom CLI with --env and --drafts options"
    )

    parser.add_argument("--env", "-e", choices=["dev", "prod"], default="dev")
    parser.add_argument("--posts", "-p", default=1)
    parser.add_argument("--no-drafts", "-nd", action="store_true")

    args = parser.parse_args()

    executor.submit(sync)
    executor.submit(run, args.posts, args.no_drafts, args.env)
