import sys
import json
import subprocess
from typing import Optional, List, Literal
from pydantic import BaseModel, Field
from langchain_anthropic import ChatAnthropic

RULES_FILE = "rules.json"


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
    """Change one or more fields on an EXISTING rule. Only set fields that actually change — leave the rest unset."""
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


def load_rules():
    with open(RULES_FILE) as f:
        return json.load(f)


def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)


def find_rule_index(rules, name):
    for i, r in enumerate(rules):
        if r["name"] == name:
            return i
    return None


def is_overly_broad(rule):
    broad_fields = ["source_addresses", "destination_addresses", "applications", "services"]
    return rule.get("action") == "allow" and all(rule.get(f) == ["any"] for f in broad_fields)


def confirm_broad_rule(rule_name):
    print(f"\n  WARNING: '{rule_name}' would allow ANY/ANY/ANY/ANY traffic — a wide-open rule.")
    answer = input("  Type 'yes i understand' to proceed anyway, or anything else to cancel: ").strip()
    return answer.lower() == "yes i understand"


def apply_create(rules, op: CreateRule):
    if find_rule_index(rules, op.name) is not None:
        print(f"Rule '{op.name}' already exists — use an update instead. No changes made.")
        sys.exit(1)

    new_rule = op.model_dump(exclude={"insert_after"})

    if is_overly_broad(new_rule) and not confirm_broad_rule(op.name):
        print("Cancelled.")
        sys.exit(1)

    if op.insert_after is None:
        rules.append(new_rule)
        position = "at the end"
    else:
        idx = find_rule_index(rules, op.insert_after)
        if idx is None:
            print(f"Can't insert after '{op.insert_after}' — no rule with that name exists. No changes made.")
            sys.exit(1)
        rules.insert(idx + 1, new_rule)
        position = f"directly after '{op.insert_after}'"

    print(f"\nWill CREATE rule '{op.name}' ({position}): "
          f"{new_rule['action']} {new_rule['source_zones']}->{new_rule['destination_zones']}, "
          f"apps={new_rule['applications']}")
    return rules


def apply_update(rules, op: UpdateRule):
    idx = find_rule_index(rules, op.name)
    if idx is None:
        print(f"No rule named '{op.name}' exists — nothing to update. No changes made.")
        sys.exit(1)

    changes = op.model_dump(exclude={"name"}, exclude_none=True)
    if not changes:
        print(f"No fields were specified to change on '{op.name}'. No changes made.")
        sys.exit(1)

    before = dict(rules[idx])
    rules[idx].update(changes)

    if is_overly_broad(rules[idx]) and not confirm_broad_rule(op.name):
        print("Cancelled.")
        sys.exit(1)

    print(f"\nWill UPDATE rule '{op.name}':")
    for field, new_value in changes.items():
        print(f"  {field}: {before.get(field)!r} -> {new_value!r}")
    return rules


def apply_delete(rules, op: DeleteRule):
    idx = find_rule_index(rules, op.name)
    if idx is None:
        print(f"No rule named '{op.name}' exists — nothing to delete. No changes made.")
        sys.exit(1)

    print(f"\nWill DELETE rule '{op.name}': {rules[idx]}")
    del rules[idx]
    return rules


def main():
    if len(sys.argv) < 2:
        print('Usage: python3 agent.py "describe the rule change in plain English"')
        sys.exit(1)

    instruction = " ".join(sys.argv[1:])

    llm = ChatAnthropic(model="claude-haiku-4-5-20251001", temperature=0, max_tokens=1024)
    llm_with_tools = llm.bind_tools([CreateRule, UpdateRule, DeleteRule])

    response = llm_with_tools.invoke(
        "You manage a Palo Alto firewall security policy. Translate the user's "
        "request into exactly one tool call — create, update, or delete a rule. "
        "Never invent zone, address, or application names the user didn't mention "
        "or imply; ask yourself if you're guessing before filling a field. "
        f"User request: {instruction}"
    )

    tool_calls = response.tool_calls
    if not tool_calls:
        print("Claude didn't return a tool call — it may have responded with plain text instead.")
        print(response.content)
        sys.exit(1)
    if len(tool_calls) > 1:
        print(f"Claude returned {len(tool_calls)} tool calls for one instruction — "
              "treating that as ambiguous rather than guessing which to apply:")
        for tc in tool_calls:
            print(f"  - {tc['name']}: {tc['args']}")
        sys.exit(1)

    call = tool_calls[0]
    tool_map = {
        "CreateRule": (CreateRule, apply_create),
        "UpdateRule": (UpdateRule, apply_update),
        "DeleteRule": (DeleteRule, apply_delete),
    }

    if call["name"] not in tool_map:
        print(f"Unknown tool name returned: {call['name']}")
        sys.exit(1)

    model_cls, handler = tool_map[call["name"]]
    op = model_cls(**call["args"])

    print(f"Interpreted as: {call['name']}({call['args']})")
    confirm = input("\nIs that what you meant? [y/N] ").strip().lower()
    if confirm != "y":
        print("Cancelled — nothing written.")
        sys.exit(0)

    rules = load_rules()
    candidate_rules = handler(rules, op)

    # rules.json is only written after apply_rules.py actually succeeds — not here.
    # Writing it before the real terraform apply/commit would let the manifest claim
    # a change that was never confirmed live.
    result = subprocess.run(
        ["python3", "apply_rules.py", "--rules-in", json.dumps(candidate_rules)]
    )

    if result.returncode == 0:
        save_rules(candidate_rules)
        print(f"\n{RULES_FILE} updated — apply confirmed successful.")
    else:
        print(f"\napply_rules.py did not complete successfully — {RULES_FILE} was NOT updated. "
              "The candidate change above was not persisted to the manifest. Check the output "
              "above, fix whatever's wrong, and either retry this instruction or run "
              "`terraform plan` directly to see current state.")
        sys.exit(1)


if __name__ == "__main__":
    main()
