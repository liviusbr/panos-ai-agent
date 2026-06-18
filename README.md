# panos-ai-agent

A natural language interface for managing Palo Alto Networks (PAN-OS) security policy through Terraform. Describe a rule change in plain English, review the actual `terraform plan` diff, and apply it only after confirming both the AI's interpretation and the real infrastructure change — available as a CLI tool or a web dashboard.

## What this does

Most "AI agent" demos let a model generate config and apply it directly. This one is built around a different assumption: an LLM should never be the thing deciding what changes on a firewall, only the thing translating intent into a structured, reviewable proposal. Every change goes through the same pipeline regardless of entry point:

```
natural language instruction
        │
        ▼
Claude (tool calling — not free-text generation)
        │
        ▼
validated CreateRule / UpdateRule / DeleteRule
        │
        ▼
candidate rule list (in memory, nothing written yet)
        │
        ▼
render to Terraform HCL → terraform plan
        │
        ▼
human reviews the actual diff
        │
        ▼
terraform apply → PAN-OS commit (polled to completion)
        │
        ▼
rules.json updated — only now, only on confirmed success
```

The manifest (`rules.json`) is only ever written after a real, confirmed `terraform apply` succeeds — not the moment a human approves the AI's interpretation, and not the moment Terraform pushes candidate config. Both the CLI (`agent.py`) and the web app (`webapp.py`) enforce this. It's what stops the tracked rule list from silently drifting out of sync with the firewall if a plan gets reviewed and rejected partway through, or if a downstream step fails after the policy push itself succeeds.

## Why Terraform, not direct API calls

This sits on top of an existing Terraform-managed PAN-OS baseline (zones, interfaces, virtual router, NAT) rather than bypassing it. The security policy is a single `panos_security_policy` resource managing the entire ordered rulebase as nested `rule` blocks — which means individual rule changes can't be split across separate Terraform resources the way some other PAN-OS resource types allow. The workaround here is a manifest model: `rules.json` is the ordered source of truth, and `render_policy.py` regenerates the *entire* policy resource from it on every change. Order in the JSON list is order on the firewall.

## Project structure

```
.
├── main.tf                        # root module: panos-baseline + Ansible inventory + commit/day-2 triggers
├── providers.tf                   # panos/null/local provider requirements
├── variables.tf / outputs.tf
├── modules/panos-baseline/
│   ├── main.tf                    # zones, interfaces, virtual router, address object
│   ├── variables.tf
│   └── policies.tf                # generated — do not edit by hand
├── ansible/
│   ├── playbook.yml                # day-2 config: hostname, DNS, NTP, timezone
│   └── group_vars/
├── commit.py                      # PAN-OS API commit, with job polling (not fire-and-forget)
├── render_policy.py               # rules.json → policies.tf (shared by CLI and web app)
├── apply_rules.py                 # CLI: render + plan + confirm + apply
├── agent.py                       # CLI: natural language → tool call → rules.json → apply_rules.py
├── webapp.py                      # FastAPI backend: same pipeline, exposed over HTTP as a job flow
├── static/index.html              # vanilla HTML/CSS/JS dashboard
├── .env.sh.example                # template for required credentials — copy to .env.sh
└── rules.json                     # the manifest — ordered list of security rules
```

## Prerequisites

- Terraform >= 1.5
- Python 3.10+
- A PAN-OS firewall (or PAN-OS VE lab) reachable over HTTPS, with an admin account
- An Anthropic API key ([console.anthropic.com](https://console.anthropic.com))

## Setup

```bash
git clone https://github.com/liviusbr/panos-ai-agent.git
cd panos-ai-agent

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

terraform init
```

Credentials are needed in **two places**, since Terraform's provider and `commit.py`'s direct API calls aren't the same code path. `terraform.tfvars` (gitignored) covers the provider:

```hcl
panos_hostname     = "<firewall-management-ip>"
panos_username     = "admin"
panos_password     = "<password>"
panos_new_hostname = "PA-VM-Lab7"
ntp_server         = "pool.ntp.org"
dns_primary        = "8.8.8.8"
dns_secondary      = "8.8.4.4"
```

Everything else — `commit.py` and Claude — reads from environment variables. Copy the template and fill it in:

```bash
cp .env.sh.example .env.sh
chmod 600 .env.sh
nano .env.sh   # fill in real values
```

**Every new shell** that runs `agent.py` or `uvicorn` needs:

```bash
source venv/bin/activate
source .env.sh
```

This matters more than it looks like it should — see Troubleshooting below.

## Usage

### CLI

```bash
python3 agent.py "allow ssl from untrust to the web server"
python3 agent.py "change allow-rdp-test to deny instead of allow"
python3 agent.py "delete the allow-rdp-test rule"
```

Each call prints Claude's structured interpretation for confirmation, then hands the candidate rule list to `apply_rules.py`, which shows the real `terraform plan` diff and asks for a second, separate confirmation before touching the firewall. `rules.json` is only written if that succeeds.

### Web dashboard

```bash
source venv/bin/activate
source .env.sh
uvicorn webapp:app --host 0.0.0.0 --port 8000
```

On startup, it checks for `ANTHROPIC_API_KEY`, `PANOS_HOSTNAME`, `PANOS_USERNAME`, `PANOS_PASSWORD` and prints a loud warning if any are missing — interpreting will still work without them, but plan/apply will fail at the commit step.

Open `http://<host>:8000`. The chat panel walks through interpret → plan → apply as buttons; the right-hand panel shows the live rulebase and refreshes after every successful apply. Every interpret/plan/apply is also logged in full to the terminal running `uvicorn` — check there first if the dashboard's error card seems vague, since the in-browser error display is intentionally generic.

## Troubleshooting

A few things that aren't obvious until they bite you, all earned the hard way:

**"Missing required environment variable" from the dashboard, even though you definitely exported it somewhere.** A process's environment is fixed at the moment it launches — `export`-ing a variable in some other terminal, or even in the same terminal *after* `uvicorn` is already running, does nothing to that running process. Stop `uvicorn` (Ctrl+C), `source .env.sh` in that same shell, then start it again. To check what a running process's environment actually contains, without guessing: `cat /proc/$(pgrep -f 'uvicorn webapp:app')/environ | tr '\0' '\n' | grep PANOS_`.

**`terraform apply` shows "Modifications complete" for the policy resource, then fails anyway.** This almost always means the policy push to PAN-OS candidate config succeeded, but the separate `commit.py` step afterward failed — usually a missing env var in whatever shell launched the process, occasionally a PAN-OS API response shape `commit.py` didn't parse correctly. Read the actual error text under "Modifications complete," not just the generic "Apply failed" banner.

**The rule table in PAN-OS's GUI shows a rule, but you're not sure it's actually live.** Policies > Security always displays candidate configuration, regardless of whether it's been committed. To know what's actually enforced, open the Commit dialog (or Task Manager's job history) and check the most recent job's Result and Details.

**`terraform state show` and the live firewall disagree.** `terraform state show` only reads the local state file — it never contacts the device. `terraform plan` always refreshes against the live API first (watch for the "Refreshing state..." lines), so it's the one to trust for current ground truth, not `state show`.

## Design notes and known limitations

- **App-ID name validation isn't built yet.** The LLM occasionally guesses a plausible-sounding but invalid application or service keyword (e.g. inventing `http` instead of the real App-ID name `web-browsing`). PAN-OS rejects these at apply time rather than silently accepting them, which is the correct failure mode, but it costs a plan/apply cycle. Validating proposed `applications`/`services` values against PAN-OS's actual App-ID list before rendering Terraform would catch this earlier.
- **Single shared policy resource.** Because the whole rulebase is one Terraform resource, this isn't designed for concurrent multi-engineer editing — there's a lock around plan/apply to prevent the web app's own requests from colliding, but it's still a single source of truth, not a distributed one.
- **In-memory job store.** The web app's pending interpret → plan → apply state lives in process memory. Restarting the server mid-flow loses any unconfirmed job (already-applied changes are unaffected, since `rules.json` and Terraform state are the durable source of truth).
- **Tested against the classic `PaloAltoNetworks/panos` provider (~1.11).** The newer plugin-framework rewrite of the provider uses a different resource schema (`panos_security_policy_rules` with nested `location`/`position` blocks) and would need different Terraform, though the agent layer (Claude tool calling → manifest → plan/apply) would carry over conceptually.

## Security

- No credentials are hardcoded anywhere in this repo — `.gitignore` excludes `*.tfvars`, `*.tfstate*`, `tfplan*`, `.env.sh`, and the generated Ansible inventory, all of which can contain or resolve to real secrets.
- `rules.json` is checked in and reflects the actual rulebase, including any internal addressing scheme in use — review it before publishing if that's a concern for your environment.
- Every create/update that would result in an `allow` rule with `any` source, destination, application, and service simultaneously triggers an explicit warning requiring separate confirmation, in both the CLI and the dashboard.
