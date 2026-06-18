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

RULES_FILE = Path("rules.json")
POLICIES_TF = Path("modules/panos-baseline/policies.tf")

app = FastAPI()

JOBS: dict = {}
JOBS_LOCK = threading.Lock()
TERRAFORM_LOCK = threading.Lock()


class CreateRule(BaseModel):
    """Create a brand new security rule on the firewall."""
    name: str = Field(description="Unique name for the new rule")
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
    """Pure function: returns (candidate_rules, summary, warnings). No disk writes, no input()."""
    rules = json.loads(json.dumps(rules))
    warnings = []

    if tool_name == "CreateRule":
        op = CreateRule(**args)
        if find_rule_index(rules, op.name) is not None:
            raise ValueError(f"Rule '{op.name}' already exists — use an update instead.")
        new_rule = op.model_dump(exclude={"insert_after"})
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
        return {"error": "llm_call_failed", "message": str(e)}

    tool_calls = response.tool_calls
    if not tool_calls:
        return {"error": "no_tool_call",
                "message": response.content or "Claude responded with plain text instead of a tool call."}
    if len(tool_calls) > 1:
        return {"error": "ambiguous",
                "message": f"Got {len(tool_calls)} tool calls for one instruction — refusing to guess which to apply."}

    call = tool_calls[0]
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
        code, output = run(["terraform", "plan", f"-out={planfile}", "-detailed-exitcode"])
        # The saved planfile is self-contained — terraform apply reads it directly and
        # never re-reads policies.tf. Safe to put the real file back right away rather
        # than leave it "staged" while this job waits for you to review and confirm.
        restore_policies_tf_from_disk()

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
        # If a different job applied in between this one's plan and apply steps,
        # terraform detects the state moved since this plan was captured and refuses
        # rather than applying blind against an outdated snapshot.
        code, output = run(["terraform", "apply", job["planfile"]])
        Path(job["planfile"]).unlink(missing_ok=True)

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


@app.get("/", response_class=HTMLResponse)
def index():
    return Path("static/index.html").read_text()
