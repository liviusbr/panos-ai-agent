import subprocess
import sys

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

def main():
    run(["python3", "render_policy.py"])

    plan = run(["terraform", "plan", "-out=tfplan", "-detailed-exitcode"], check=False)

    if plan.returncode == 1:
        print("terraform plan failed — see output above. Nothing applied.")
        sys.exit(1)
    if plan.returncode == 0:
        print("No changes — nothing to apply.")
        return

    answer = input("\nApply this plan? [y/N] ").strip().lower()
    if answer != "y":
        print("Not applying.")
        return

    apply_result = run(["terraform", "apply", "tfplan"], check=False)
    if apply_result.returncode != 0:
        print("APPLY FAILED — config may be partially applied. "
              "Check `terraform state list` and the firewall GUI directly "
              "before assuming anything about current state.")
        sys.exit(1)

    # apply succeeding here means commit.py's local-exec provisioner also
    # exited 0 — and commit.py only exits 0 after polling the PAN-OS job
    # to FIN/OK, or confirming there was nothing new to commit. A failed
    # or stuck commit fails the provisioner, which fails this apply. So
    # this isn't a guess — it's commit.py's own verified outcome.
    print("terraform apply exited 0 — PAN-OS confirmed the commit "
          "(or had nothing new to commit). Rule changes are live.")

if __name__ == "__main__":
    main()
