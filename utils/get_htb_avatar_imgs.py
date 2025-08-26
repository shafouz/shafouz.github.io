import dotenv
import glob
import re
import requests
import os

dotenv.load_dotenv("./.env")

files = glob.glob("_posts/*htb-*.md")
for file in files:
    machine_name = re.search("htb-(.+?).md", file).group(1)
    machine_name = machine_name.lower()
    print(machine_name)

    if os.path.exists(f"./assets/img/{machine_name}.png"):
        continue

    root_url = "https://labs.hackthebox.com/"
    htb_token = os.getenv("HTB_TOKEN")

    url = f"{root_url}api/v4/machine/profile/{machine_name}"

    headers = {
        "Authorization": f"Bearer {htb_token}",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0"
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()

    json_data = response.json()
    avatar_url = root_url + "storage" + json_data["info"]["avatar"]

    os.system(f"curl {avatar_url} -o ./assets/img/{machine_name}.png")
