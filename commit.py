import os
import re
import sys
import time
import requests
import urllib3
import xml.etree.ElementTree as ET

urllib3.disable_warnings()


def require_env(name):
    value = os.environ.get(name)
    if not value:
        print(f"Missing required environment variable: {name}")
        sys.exit(1)
    return value


HOSTNAME = require_env("PANOS_HOSTNAME")
USERNAME = require_env("PANOS_USERNAME")
PASSWORD = require_env("PANOS_PASSWORD")
POLL_INTERVAL_SECONDS = 3
POLL_TIMEOUT_SECONDS = 120


def api_call(params):
    r = requests.get(f"https://{HOSTNAME}/api/", params=params, verify=False, timeout=15)
    r.raise_for_status()
    return ET.fromstring(r.text)


def get_api_key():
    root = api_call({"type": "keygen", "user": USERNAME, "password": PASSWORD})
    if root.get("status") != "success":
        print(f"Failed to get API key. Response: {ET.tostring(root, encoding='unicode')}")
        sys.exit(1)
    key = root.findtext(".//key")
    if not key:
        print(f"No <key> in keygen response: {ET.tostring(root, encoding='unicode')}")
        sys.exit(1)
    return key


def extract_msg_text(root):
    msg_el = root.find(".//msg")
    if msg_el is None:
        return ""
    direct_text = (msg_el.text or "").strip()
    if direct_text:
        return direct_text
    lines = [line.text or "" for line in msg_el.findall("line")]
    return "\n".join(lines).strip()


def start_commit(api_key):
    root = api_call({"type": "commit", "cmd": "<commit></commit>", "key": api_key})
    print(f"Commit request response: {ET.tostring(root, encoding='unicode')}")

    if root.get("status") != "success":
        print("Commit request itself was rejected — see response above.")
        sys.exit(1)

    job_id = root.findtext(".//job")
    if job_id:
        return job_id

    msg = extract_msg_text(root)
    if "no changes to commit" in msg.lower():
        print("Nothing to commit — candidate already matches running config.")
        return None

    print(f"No job ID returned and message didn't match a known case: '{msg}' — treating as failure.")
    sys.exit(1)


def poll_job(api_key, job_id):
    elapsed = 0
    while elapsed < POLL_TIMEOUT_SECONDS:
        root = api_call({
            "type": "op",
            "cmd": f"<show><jobs><id>{job_id}</id></jobs></show>",
            "key": api_key,
        })
        job = root.find(".//job")
        status = job.findtext("status") if job is not None else None
        result = job.findtext("result") if job is not None else None
        print(f"Job {job_id} status={status} result={result} (elapsed {elapsed}s)")

        if status == "FIN":
            detail = job.findtext("details/line") or ""
            if result == "OK":
                print(f"Commit job {job_id} finished successfully. {detail}")
                return True
            print(f"Commit job {job_id} finished but did not succeed (result={result}). {detail}")
            return False

        time.sleep(POLL_INTERVAL_SECONDS)
        elapsed += POLL_INTERVAL_SECONDS

    print(f"Timed out after {POLL_TIMEOUT_SECONDS}s waiting for job {job_id}.")
    return False


def main():
    api_key = get_api_key()
    job_id = start_commit(api_key)
    if job_id is None:
        return
    if not poll_job(api_key, job_id):
        sys.exit(1)


if __name__ == "__main__":
    main()
