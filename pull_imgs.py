#!/bin/env python3

import re
import os
import glob
import shutil

assert False, "Fix this so you don't leak stuff"

HTB_PATH = "/home/shafou/workspace/projects/htb/"

pngs = glob.glob(f"{HTB_PATH}/**/imgs/*.png", recursive=True)

for png in pngs:
    if re.search(r"[a-zA-Z]+?[0-9]{1,2}.png$", png):
        basename = os.path.basename(png)

        if os.path.exists(os.path.join("./assets/img", basename)):
            num = int(re.search("([0-9]{1,2}).png", basename).group(1)) + 1
            name, ext = re.split("[0-9]{1,2}", basename, maxsplit=1)
            new_name = name + str(num) + ext

            # print(os.path.join("./assets/img", new_name))
            shutil.copy(png, os.path.join("./assets/img", new_name))
            continue

        shutil.copy(png, os.path.join("./assets/img"))
