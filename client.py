import requests
from inotify_simple import INotify, flags
import re
from datetime import datetime
import time
import json

def get_public_ip():
    try:
        response = requests.get('https://httpbin.org/ip')
        if response.status_code == 200:
            return response.json().get('origin')
    except Exception as e:
        pass
    return None

config = {
    "api_url": "http://135.181.193.165:5000"
}

processed_lines = []

try:
    with open("data.json", "r") as f:
        processed_lines = json.load(f)["processed_lines"]
except Exception as e:
    pass

def save_data(data):
    with open("data.json", "w") as f:
        json.dump(data, f)

if not config.get("api_url").endswith("/"):
    config["api_url"] += "/"

api_url = config["api_url"]

def get_token(public_ip):
    while True:
        try:
            response = requests.post(f"{api_url}register/", json={"ip_address": public_ip})
            if response.status_code == 200:
                return response.json().get("token")
        except requests.exceptions.ConnectionError:
            time.sleep(10)  # Retry after 10 seconds if the server is down
        except Exception as e:
            pass

token = get_token(get_public_ip())

def report_attack(attack_data):
    while True:
        try:
            url = f"{api_url}attacks/"
            jsondata = {
                "ip": attack_data["ip"],
                "time": attack_data["time"],
                "text": attack_data["text"]
            }
            response = requests.post(url, json=jsondata, headers={"Token": token})
            if response.status_code == 200:
                return
        except requests.exceptions.ConnectionError:
            time.sleep(10)  # Retry after 10 seconds if the server is down
        except Exception as e:
            pass

# Function to parse and extract attack information from auth.log lines
def parse_auth_log_line(line):
    # Patterns for both failed password and non-existing user attempts
    password_pattern = r"sshd\[\d+\]: Failed password for .* from (.+) port \d+"
    user_pattern = r"sshd\[\d+\]: Invalid user (.+) from (.+) port \d+"

    password_match = re.search(password_pattern, line)
    user_match = re.search(user_pattern, line)

    if password_match:
        attacker_ip = password_match.group(1)
        attack_time = datetime.now().isoformat()
        return {"ip": attacker_ip, "time": attack_time, "text": line}

    if user_match:
        attacker_ip = user_match.group(2)
        attack_time = datetime.now().isoformat()
        return {"ip": attacker_ip, "time": attack_time, "text": line}

    return None

def watch_auth_log():
    inotify = INotify()
    watch_flags = flags.MODIFY | flags.CLOSE_WRITE

    watch_descriptor = inotify.add_watch('/var/log/auth.log', watch_flags)

    try:
        while True:
            events = inotify.read()

            for event in events:
                if event.mask & flags.MODIFY or event.mask & flags.CLOSE_WRITE:
                    with open('/var/log/auth.log') as auth_log:
                        auth_log_lines = auth_log.readlines()
                        new_lines = [line for line in auth_log_lines if line not in processed_lines]

                        for line in new_lines:
                            attack_data = parse_auth_log_line(line)
                            if attack_data:
                                report_attack(attack_data)
                            processed_lines.append(line)

    except KeyboardInterrupt:
        inotify.rm_watch(watch_descriptor)
        data = {"processed_lines": processed_lines}
        save_data(data)

if __name__ == '__main__':
    watch_auth_log()
