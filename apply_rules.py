import sys
import json
import subprocess

def run(cmd, check=True):
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if check and result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        sys.exit(1)
    return result

def render(rules):
    from render_policy import render_rules_to_string
    with open("modules/panos-baseline/policies.tf", "w") as f:
        f.write(render_rules_to_string(rules))

def main():
    rules_in = None
    if "--rules-in" in sys.argv:
        idx = sys.argv.index("--rules-in")
        rules_in = json.loads(sys.argv[idx + 1])

    if rules_in is not None:
        render(rules_in)
    else:
        run(["python3", "render_policy.py"])

    plan = run(["terraform", "plan", "-no-color", "-out=tfplan", "-detailed-exitcode"], check=False)

    if plan.returncode == 1:
        print("terraform plan failed — see output above. Nothing applied.")
        sys.exit(1)
    if plan.returncode == 0:
        print("No changes — nothing to apply.")
        return

    answer = input("\nApply this plan? [y/N] ").strip().lower()
    if answer != "y":
        print("Not applying.")
        sys.exit(1)

    apply_result = run(["terraform", "apply", "-no-color", "tfplan"], check=False)
    if apply_result.returncode != 0:
        print("APPLY FAILED — config may be partially applied. "
              "Check `terraform state list` and the firewall GUI directly "
              "before assuming anything about current state.")
        sys.exit(1)

    print("terraform apply exited 0 — PAN-OS confirmed the commit "
          "(or had nothing new to commit). Rule changes are live.")

if __name__ == "__main__":
    main()
