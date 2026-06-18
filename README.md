panos-ai-agent
A natural language interface for managing Palo Alto Networks (PAN-OS) security policy through Terraform. Describe a rule change in plain English, review the actual `terraform plan` diff, and apply it only after confirming both the AI's interpretation and the real infrastructure change — available as a CLI tool or a web dashboard.
What this does
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
The manifest (`rules.json`) is only ever written after a real, confirmed `terraform apply` succeeds — not the moment a human approves the AI's interpretation. That distinction matters: it's what stops the tracked rule list from silently drifting out of sync with the firewall if a plan gets reviewed and rejected partway through.
Why Terraform, not direct API calls
This sits on top of an existing Terraform-managed PAN-OS baseline (zones, interfaces, virtual router, NAT) rather than bypassing it. The security policy is a single `panos_security_policy` resource managing the entire ordered rulebase as nested `rule` blocks — which means individual rule changes can't be split across separate Terraform resources the way some other PAN-OS resource types allow. The workaround here is a manifest model: `rules.json` is the ordered source of truth, and `render_policy.py` regenerates the entire policy resource from it on every change. Order in the JSON list is order on the firewall.
Project structure
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
└── rules.json                     # the manifest — ordered list of security rules
```
Prerequisites
Terraform >= 1.5
Python 3.10+
A PAN-OS firewall (or PAN-OS VE lab) reachable over HTTPS, with an admin account
An Anthropic API key (console.anthropic.com)
Setup
```bash
git clone https://github.com/liviusbr/panos-ai-agent.git
cd panos-ai-agent

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt   # fastapi, uvicorn, langchain-anthropic, jinja2, requests

terraform init
```
Credentials are needed in two places, since Terraform's provider and `commit.py`'s direct API calls aren't the same code path:
```bash
# terraform.tfvars (gitignored — never commit this)
panos_hostname     = "<firewall-management-ip>"
panos_username     = "admin"
panos_password     = "<password>"
panos_new_hostname = "PA-VM-Lab7"
ntp_server         = "pool.ntp.org"
dns_primary        = "8.8.8.8"
dns_secondary      = "8.8.4.4"
```
```bash
# exported in the same shell that runs terraform apply / uvicorn
export PANOS_HOSTNAME="<firewall-management-ip>"
export PANOS_USERNAME="admin"
export PANOS_PASSWORD="<password>"
export ANTHROPIC_API_KEY="<your-key>"
```
Usage
CLI
```bash
python3 agent.py "allow ssl from untrust to the web server"
python3 agent.py "change allow-rdp-test to deny instead of allow"
python3 agent.py "delete the allow-rdp-test rule"
```
Each call prints Claude's structured interpretation for confirmation, then hands off to `apply_rules.py`, which shows the real `terraform plan` diff and asks for a second, separate confirmation before touching the firewall.
Web dashboard
```bash
uvicorn webapp:app --host 0.0.0.0 --port 8000
```
Open `http://<host>:8000`. The chat panel walks through the same interpret → plan → apply stages as buttons instead of terminal prompts; the right-hand panel shows the live rulebase and refreshes after every successful apply.
Design notes and known limitations
App-ID name validation isn't built yet. The LLM occasionally guesses a plausible-sounding but invalid application or service keyword (e.g. inventing `http` instead of the real App-ID name `web-browsing`). PAN-OS rejects these at apply time rather than silently accepting them, which is the correct failure mode, but it costs a plan/apply cycle. Validating proposed `applications`/`services` values against PAN-OS's actual App-ID list before rendering Terraform would catch this earlier.
Single shared policy resource. Because the whole rulebase is one Terraform resource, this isn't designed for concurrent multi-engineer editing — there's a lock around plan/apply to prevent the web app's own requests from colliding, but it's still a single source of truth, not a distributed one.
In-memory job store. The web app's pending interpret → plan → apply state lives in process memory. Restarting the server mid-flow loses any unconfirmed job (already-applied changes are unaffected, since `rules.json` and Terraform state are the durable source of truth).
Tested against the classic `PaloAltoNetworks/panos` provider (~1.11). The newer plugin-framework rewrite of the provider uses a different resource schema (`panos_security_policy_rules` with nested `location`/`position` blocks) and would need different Terraform, though the agent layer (Claude tool calling → manifest → plan/apply) would carry over conceptually.
Security
No credentials are hardcoded anywhere in this repo — `.gitignore` excludes `*.tfvars`, `*.tfstate*`, `tfplan*`, and the generated Ansible inventory, all of which can contain or resolve to real secrets.
`rules.json` is checked in and reflects the actual rulebase, including any internal addressing scheme in use — review it before publishing if that's a concern for your environment.
Every create/update that would result in an `allow` rule with `any` source, destination, application, and service simultaneously triggers an explicit warning requiring separate confirmation, in both the CLI and the dashboard.
