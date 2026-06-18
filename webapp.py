import json
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Optional, List, Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from langchain_anthropic import ChatAnthropic

from render_policy import render_rules_to_string
import panos_cache

RULES_FILE = Path("rules.json")
POLICIES_TF = Path("modules/panos-baseline/policies.tf")

import os

REQUIRED_ENV_VARS = ["ANTHROPIC_API_KEY", "PANOS_HOSTNAME", "PANOS_USERNAME", "PANOS_PASSWORD"]
_missing = [v for v in REQUIRED_ENV_VARS if not os.environ.get(v)]
if _missing:
    print("=" * 60)
    print("WARNING: missing in THIS shell's environment:")
    for v in _missing:
        print(f"  - {v}")
    print("Interpreting will still work, but plan/apply will fail at")
    print("the commit step. Stop this process (Ctrl+C), `source .env.sh`,")
    print("and restart before relying on this server.")
    print("=" * 60)

app = FastAPI()

JOBS: dict = {}
JOBS_LOCK = threading.Lock()
TERRAFORM_LOCK = threading.Lock()


class CreateRule(BaseModel):
    """Create a brand new security rule on the firewall."""
    name: str = Field(description="Unique name for the new rule, using hyphens between words (e.g. 'allow-ssh-from-internet'), matching the style of existing rules — never spaces.")
    source_zones: List[str] = Field(description="Source security zones, e.g. ['trust']")
    source_addresses: List[str] = Field(default=["any"])
    source_users: List[str] = Field(default=["any"])
    destination_zones: List[str] = Field(description="Destination security zones")
    destination_addresses: List[str] = Field(default=["any"])
    applications: List[str] = Field(
        default=["any"],
        description="App-ID application names PAN-OS recognizes, e.g. 'ms-rdp', 'ssl', "
                    "'web-browsing', 'icmp', 'ping', or 'any'. This is Layer 7 — what kind of traffic it is."
    )
    services: List[str] = Field(
        default=["application-default"],
        description="Layer 4 service reference ONLY. Must be 'any', 'application-default', or the "
                    "exact name of an existing PAN-OS Service object. NEVER put an application name "
                    "here — when in doubt, leave this as 'application-default'."
    )
    categories: List[str] = Field(default=["any"])
    action: Literal["allow", "deny"]
    log_end: bool = Field(default=True)
    insert_after: Optional[str] = Field(
        default=None,
        description="Name of an existing rule this new rule should sit directly after. Omit to append at the end."
    )


class UpdateRule(BaseModel):
    """Change one or more fields on an EXISTING rule. Only set fields that actually change."""
    name: str = Field(description="Name of the existing rule to modify")
    source_zones: Optional[List[str]] = None
    source_addresses: Optional[List[str]] = None
    source_users: Optional[List[str]] = None
    destination_zones: Optional[List[str]] = None
    destination_addresses: Optional[List[str]] = None
    applications: Optional[List[str]] = None
    services: Optional[List[str]] = None
    categories: Optional[List[str]] = None
    action: Optional[Literal["allow", "deny"]] = None
    log_end: Optional[bool] = None


class DeleteRule(BaseModel):
    """Permanently remove an existing rule by name."""
    name: str = Field(description="Name of the rule to delete")


TOOLS = [CreateRule, UpdateRule, DeleteRule]


def load_rules():
    if not RULES_FILE.exists():
        return []
    return json.loads(RULES_FILE.read_text())


def find_rule_index(rules, name):
    for i, r in enumerate(rules):
        if r["name"] == name:
            return i
    return None


def is_overly_broad(rule):
    broad = ["source_addresses", "destination_addresses", "applications", "services"]
    return rule.get("action") == "allow" and all(rule.get(f) == ["any"] for f in broad)


def compute_candidate(rules, tool_name, args):
    rules = json.loads(json.dumps(rules))
    warnings = []

    if tool_name == "CreateRule":
        op = CreateRule(**args)
        if find_rule_index(rules, op.name) is not None:
            raise ValueError(f"Rule '{op.name}' already exists — use an update instead.")
        new_rule = op.model_dump(exclude={"insert_after"})
        invalid_apps = panos_cache.validate_applications(new_rule.get("applications", []))
        if invalid_apps:
            raise ValueError(
                f"Unknown App-ID name(s): {invalid_apps}. "
                f"These are not in PAN-OS's predefined application list. "
                f"Common examples: 'web-browsing' (not 'http'), 'ms-rdp' (not 'rdp'), "
                f"'ssl', 'ssh', 'ping', 'icmp'. Check the App-ID list at /api/appids."
            )
        if is_overly_broad(new_rule):
            warnings.append(f"'{op.name}' would allow ANY/ANY/ANY/ANY traffic — a wide-open rule.")
        if op.insert_after is None:
            rules.append(new_rule)
            position = "at the end"
        else:
            idx = find_rule_index(rules, op.insert_after)
            if idx is None:
                raise ValueError(f"Can't insert after '{op.insert_after}' — no such rule exists.")
            rules.insert(idx + 1, new_rule)
            position = f"directly after '{op.insert_after}'"
        summary = (f"CREATE '{op.name}' ({position}): {new_rule['action']} "
                   f"{new_rule['source_zones']} -> {new_rule['destination_zones']}, "
                   f"apps={new_rule['applications']}")

    elif tool_name == "UpdateRule":
        op = UpdateRule(**args)
        idx = find_rule_index(rules, op.name)
        if idx is None:
            raise ValueError(f"No rule named '{op.name}' exists — nothing to update.")
        changes = op.model_dump(exclude={"name"}, exclude_none=True)
        if not changes:
            raise ValueError(f"No fields were specified to change on '{op.name}'.")
        before = dict(rules[idx])
        rules[idx].update(changes)
        if "applications" in changes:
            invalid_apps = panos_cache.validate_applications(changes["applications"])
            if invalid_apps:
                raise ValueError(
                    f"Unknown App-ID name(s): {invalid_apps}. "
                    f"Check valid names at /api/appids."
                )
        if is_overly_broad(rules[idx]):
            warnings.append(f"'{op.name}' would allow ANY/ANY/ANY/ANY traffic after this change.")
        lines = [f"UPDATE '{op.name}':"]
        for field, new_value in changes.items():
            lines.append(f"  {field}: {before.get(field)!r} -> {new_value!r}")
        summary = "\n".join(lines)

    elif tool_name == "DeleteRule":
        op = DeleteRule(**args)
        idx = find_rule_index(rules, op.name)
        if idx is None:
            raise ValueError(f"No rule named '{op.name}' exists — nothing to delete.")
        summary = f"DELETE '{op.name}': {rules[idx]}"
        del rules[idx]

    else:
        raise ValueError(f"Unknown tool: {tool_name}")

    return rules, summary, warnings


def restore_policies_tf_from_disk():
    POLICIES_TF.write_text(render_rules_to_string(load_rules()))


def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


class InterpretRequest(BaseModel):
    instruction: str


@app.post("/api/interpret")
def interpret(req: InterpretRequest):
    try:
        llm = ChatAnthropic(model="claude-haiku-4-5-20251001", temperature=0, max_tokens=1024)
        llm_with_tools = llm.bind_tools(TOOLS)
        response = llm_with_tools.invoke(
            "You manage a Palo Alto firewall security policy. Translate the user's "
            "request into exactly one tool call — create, update, or delete a rule. "
            "Never invent zone, address, or application names the user didn't mention "
            "or imply; ask yourself if you're guessing before filling a field. "
            f"User request: {req.instruction}"
        )
    except Exception as e:
        print(f"\n=== interpret FAILED: {e} ===\n", flush=True)
        return {"error": "llm_call_failed", "message": str(e)}

    tool_calls = response.tool_calls
    if not tool_calls:
        print(f"\n=== interpret: no tool call. raw content: {response.content!r} ===\n", flush=True)
        return {"error": "no_tool_call",
                "message": response.content or "Claude responded with plain text instead of a tool call."}
    if len(tool_calls) > 1:
        return {"error": "ambiguous",
                "message": f"Got {len(tool_calls)} tool calls for one instruction — refusing to guess which to apply."}

    call = tool_calls[0]
    print(f"\n=== interpret: '{req.instruction}' -> {call['name']}({call['args']}) ===\n", flush=True)

    try:
        rules = load_rules()
        candidate_rules, summary, warnings = compute_candidate(rules, call["name"], call["args"])
    except Exception as e:
        return {"error": "validation_failed", "message": str(e)}

    job_id = str(uuid.uuid4())
    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "interpreted",
            "tool_name": call["name"],
            "tool_args": call["args"],
            "candidate_rules": candidate_rules,
        }

    return {
        "job_id": job_id,
        "tool_name": call["name"],
        "tool_args": call["args"],
        "summary": summary,
        "warnings": warnings,
    }


@app.post("/api/jobs/{job_id}/plan")
def plan_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Unknown job")

    planfile = f"tfplan-{job_id}"
    with TERRAFORM_LOCK:
        POLICIES_TF.write_text(render_rules_to_string(job["candidate_rules"]))
        code, output = run(["terraform", "plan", "-no-color", f"-out={planfile}", "-detailed-exitcode"])
        restore_policies_tf_from_disk()

    print(f"\n=== plan job {job_id} (exit {code}) ===\n{output}\n=== end plan {job_id} ===\n", flush=True)

    if code == 1:
        job["status"] = "plan_failed"
        return {"status": "plan_failed", "output": output}

    job["status"] = "planned"
    job["planfile"] = planfile
    return {"status": "planned", "output": output, "no_changes": code == 0}


@app.post("/api/jobs/{job_id}/apply")
def apply_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or job.get("status") != "planned":
        raise HTTPException(400, "Job must be successfully planned before it can be applied")

    with TERRAFORM_LOCK:
        code, output = run(["terraform", "apply", "-no-color", job["planfile"]])
        Path(job["planfile"]).unlink(missing_ok=True)

        print(f"\n=== apply job {job_id} (exit {code}) ===\n{output}\n=== end apply {job_id} ===\n", flush=True)

        if code != 0:
            job["status"] = "apply_failed"
            return {
                "status": "apply_failed",
                "output": output,
                "warning": "Apply failed — config may be partially applied. "
                           "Check `terraform state list` and the firewall GUI directly "
                           "before assuming anything about current state.",
            }

        RULES_FILE.write_text(json.dumps(job["candidate_rules"], indent=2))
        restore_policies_tf_from_disk()
        job["status"] = "applied"

    return {"status": "applied", "output": output}


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.pop(job_id, None)
    if job and job.get("planfile"):
        Path(job["planfile"]).unlink(missing_ok=True)
    return {"status": "cancelled"}


@app.get("/api/rules")
def get_rules():
    return load_rules()


@app.get("/api/appids")
def list_appids():
    return {"appids": panos_cache.get_appids(), "count": len(panos_cache.get_appids())}


@app.post("/api/appids/refresh")
def refresh_appids():
    data = panos_cache.refresh_cache(force=True)
    return {
        "appids_count": len(data.get("appids", [])),
        "hit_counts_supported": data.get("hit_counts_supported", False),
        "fetched_at": data.get("fetched_at"),
    }


@app.get("/api/hit-counts")
def hit_counts():
    counts = panos_cache.get_hit_counts()
    return {
        "supported": bool(counts),
        "hit_counts": counts,
    }


@app.get("/", response_class=HTMLResponse)
def index():
    return Path("static/index.html").read_text()


@app.get("/api/nat-rules")
def get_nat_rules():
    """Read NAT rules directly from the live firewall — read-only, not Terraform-managed."""
    try:
        import panos_cache
        hostname = __import__('os').environ.get("PANOS_HOSTNAME")
        username = __import__('os').environ.get("PANOS_USERNAME")
        password = __import__('os').environ.get("PANOS_PASSWORD")
        import requests, urllib3, xml.etree.ElementTree as ET
        urllib3.disable_warnings()

        # Get API key
        r = requests.get(
            f"https://{hostname}/api/",
            params={"type": "keygen", "user": username, "password": password},
            verify=False, timeout=15
        )
        key = ET.fromstring(r.text).findtext(".//key")

        # Fetch NAT rules
        r = requests.get(
            f"https://{hostname}/api/",
            params={
                "type": "config",
                "action": "get",
                "xpath": "/config/devices/entry/vsys/entry/rulebase/nat/rules",
                "key": key,
            },
            verify=False, timeout=15
        )
        root = ET.fromstring(r.text)
        rules = []
        for entry in root.findall(".//rules/entry"):
            name = entry.get("name")
            src_zones = [m.text for m in entry.findall(".//from/member")]
            dst_zones = [m.text for m in entry.findall(".//to/member")]
            src_addrs = [m.text for m in entry.findall(".//source/member")]
            dst_addrs = [m.text for m in entry.findall(".//destination/member")]

            # Source translation type
            snat = entry.find(".//source-translation")
            if snat is not None:
                if snat.find(".//dynamic-ip-and-port") is not None:
                    dip = snat.find(".//dynamic-ip-and-port")
                    if dip.find(".//interface-address") is not None:
                        iface = dip.findtext(".//interface") or "unknown"
                        snat_type = f"dynamic-ip-and-port ({iface})"
                    else:
                        translated = [m.text for m in dip.findall(".//member")]
                        snat_type = f"dynamic-ip-and-port ({', '.join(translated)})"
                elif snat.find(".//static-ip") is not None:
                    ip = snat.findtext(".//translated-address") or "unknown"
                    snat_type = f"static-ip ({ip})"
                elif snat.find(".//dynamic-ip") is not None:
                    snat_type = "dynamic-ip"
                else:
                    snat_type = "unknown"
            else:
                snat_type = "none"

            # Destination translation
            dnat = entry.find(".//destination-translation")
            if dnat is not None:
                dnat_addr = dnat.findtext(".//translated-address") or "unknown"
                dnat_port = dnat.findtext(".//translated-port")
                dnat_type = f"{dnat_addr}" + (f":{dnat_port}" if dnat_port else "")
            else:
                dnat_type = "none"

            rules.append({
                "name": name,
                "source_zones": src_zones,
                "destination_zones": dst_zones,
                "source_addresses": src_addrs,
                "destination_addresses": dst_addrs,
                "source_translation": snat_type,
                "destination_translation": dnat_type,
            })

        return {"rules": rules, "count": len(rules)}
    except Exception as e:
        return {"error": str(e), "rules": [], "count": 0}


# ── NAT Agent endpoints ────────────────────────────────────────────────────────

from nat_agent_tools import CreateNatRule, UpdateNatRule, DeleteNatRule, NAT_TOOLS
from render_nat_policy import render_nat_rules_to_string

NAT_RULES_FILE = Path("nat_rules.json")
NAT_POLICIES_TF = Path("modules/panos-baseline/nat_policy.tf")


def load_nat_rules():
    if not NAT_RULES_FILE.exists():
        return []
    return json.loads(NAT_RULES_FILE.read_text())


def restore_nat_policies_tf_from_disk():
    NAT_POLICIES_TF.write_text(render_nat_rules_to_string(load_nat_rules()))


def find_nat_rule_index(rules, name):
    for i, r in enumerate(rules):
        if r["name"] == name:
            return i
    return None


def compute_nat_candidate(rules, tool_name, args):
    rules = json.loads(json.dumps(rules))

    if tool_name == "CreateNatRule":
        op = CreateNatRule(**args)
        if find_nat_rule_index(rules, op.name) is not None:
            raise ValueError(f"NAT rule '{op.name}' already exists.")
        new_rule = op.model_dump()
        rules.append(new_rule)
        summary = (
            f"CREATE NAT '{op.name}:\\n"
            f"  src:  zones={new_rule['source_zones']}  addrs={new_rule['source_addresses']}\\n"
            f"  dst:  zone={new_rule['destination_zone']}  addrs={new_rule['destination_addresses']}\\n"
            f"  snat: {new_rule['sat_type']}"
            + (f" via {new_rule['sat_interface']}" if new_rule.get('sat_interface') else "")
            + (f"\\n  dnat: {new_rule['dat_address']}" + (f":{new_rule['dat_port']}" if new_rule.get('dat_port') else "") if new_rule.get('dat_address') else "")
        )

    elif tool_name == "UpdateNatRule":
        op = UpdateNatRule(**args)
        idx = find_nat_rule_index(rules, op.name)
        if idx is None:
            raise ValueError(f"No NAT rule named '{op.name}' exists.")
        changes = op.model_dump(exclude={"name"}, exclude_none=True)
        if not changes:
            raise ValueError(f"No fields specified to change on '{op.name}'.")
        before = dict(rules[idx])
        rules[idx].update(changes)
        lines = [f"UPDATE NAT '{op.name}':"]
        for field, new_value in changes.items():
            lines.append(f"  {field}: {before.get(field)!r} -> {new_value!r}")
        summary = "\n".join(lines)

    elif tool_name == "DeleteNatRule":
        op = DeleteNatRule(**args)
        idx = find_nat_rule_index(rules, op.name)
        if idx is None:
            raise ValueError(f"No NAT rule named '{op.name}' exists.")
        summary = f"DELETE NAT '{op.name}': {rules[idx]}"
        del rules[idx]

    else:
        raise ValueError(f"Unknown NAT tool: {tool_name}")

    return rules, summary


class NatInterpretRequest(BaseModel):
    instruction: str


@app.post("/api/nat/interpret")
def nat_interpret(req: NatInterpretRequest):
    try:
        llm = ChatAnthropic(model="claude-haiku-4-5-20251001", temperature=0, max_tokens=1024)
        llm_with_tools = llm.bind_tools(NAT_TOOLS)
        response = llm_with_tools.invoke(
            "You manage Palo Alto firewall NAT policy. Translate the user's request into "
            "exactly one tool call — create, update, or delete a NAT rule. "
            "sat_type 'dynamic-ip-and-port' is PAT/masquerade (most common for outbound). "
            "dat_address/dat_port are for destination NAT (port forwarding, DNAT). "
            "Never invent interface or address names the user didn't mention. "
            f"User request: {req.instruction}"
        )
    except Exception as e:
        print(f"\n=== nat_interpret FAILED: {e} ===\n", flush=True)
        return {"error": "llm_call_failed", "message": str(e)}

    tool_calls = response.tool_calls
    if not tool_calls:
        return {"error": "no_tool_call", "message": response.content or "No tool call returned."}
    if len(tool_calls) > 1:
        return {"error": "ambiguous", "message": f"Got {len(tool_calls)} tool calls — refusing to guess."}

    call = tool_calls[0]
    print(f"\n=== nat_interpret: '{req.instruction}' -> {call['name']}({call['args']}) ===\n", flush=True)

    try:
        rules = load_nat_rules()
        candidate_rules, summary = compute_nat_candidate(rules, call["name"], call["args"])
    except Exception as e:
        return {"error": "validation_failed", "message": str(e)}

    job_id = str(uuid.uuid4())
    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "interpreted",
            "type": "nat",
            "tool_name": call["name"],
            "tool_args": call["args"],
            "candidate_rules": candidate_rules,
        }

    return {
        "job_id": job_id,
        "tool_name": call["name"],
        "tool_args": call["args"],
        "summary": summary,
    }


@app.post("/api/nat/jobs/{job_id}/plan")
def nat_plan_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or job.get("type") != "nat":
        raise HTTPException(404, "Unknown NAT job")

    planfile = f"tfplan-{job_id}"
    with TERRAFORM_LOCK:
        NAT_POLICIES_TF.write_text(render_nat_rules_to_string(job["candidate_rules"]))
        code, output = run(["terraform", "plan", "-no-color", f"-out={planfile}", "-detailed-exitcode"])
        restore_nat_policies_tf_from_disk()

    print(f"\n=== nat_plan {job_id} (exit {code}) ===\n{output}\n=== end ===\n", flush=True)

    if code == 1:
        job["status"] = "plan_failed"
        return {"status": "plan_failed", "output": output}

    job["status"] = "planned"
    job["planfile"] = planfile
    return {"status": "planned", "output": output, "no_changes": code == 0}


@app.post("/api/nat/jobs/{job_id}/apply")
def nat_apply_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or job.get("status") != "planned" or job.get("type") != "nat":
        raise HTTPException(400, "Job must be a successfully planned NAT job")

    with TERRAFORM_LOCK:
        code, output = run(["terraform", "apply", "-no-color", job["planfile"]])
        Path(job["planfile"]).unlink(missing_ok=True)

        print(f"\n=== nat_apply {job_id} (exit {code}) ===\n{output}\n=== end ===\n", flush=True)

        if code != 0:
            job["status"] = "apply_failed"
            return {
                "status": "apply_failed",
                "output": output,
                "warning": "Apply failed — check terraform state and firewall GUI directly.",
            }

        NAT_RULES_FILE.write_text(json.dumps(job["candidate_rules"], indent=2))
        restore_nat_policies_tf_from_disk()
        job["status"] = "applied"

    return {"status": "applied", "output": output}


@app.post("/api/nat/jobs/{job_id}/cancel")
def nat_cancel_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.pop(job_id, None)
    if job and job.get("planfile"):
        Path(job["planfile"]).unlink(missing_ok=True)
    return {"status": "cancelled"}


@app.get("/api/nat/rules")
def get_nat_agent_rules():
    return load_nat_rules()
