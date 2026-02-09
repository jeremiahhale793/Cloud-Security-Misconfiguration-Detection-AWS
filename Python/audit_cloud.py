"""
audit_cloud.py

Cloud Security Misconfiguration Detection (AWS)

This script      reads Terraform outputs (terraform_outputs.json) and performs a simple
security audit of intentionally misconfigured AWS resources:
- S3 Public Access Block settings
- Security Group inbound exposure (0.0.0.0/0)
- IAM over-permissive managed policies (Allow "*" on "*")


Prereqs:
- AWS credentials configured (aws sts get-caller-identity works)
- boto3 installed (pip install boto3)
- terraform_outputs.json generated in the same folder as this script:
  From Terraform folder:
      terraform output -json > ../python/terraform_outputs.json
"""

import json
from pathlib import Path
from typing import Any, Dict, List

import boto3

HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"


def load_tf_outputs(filename: str = "terraform_outputs.json") -> Dict[str, Any]:
    """
    Loads terraform outputs from a JSON file located in the same folder as this script.
    Expected Terraform output format: {"output_name": {"value": ...}, ...}
    Returns a simple dict: {"output_name": value, ...}
    """
    base_dir = Path(__file__).parent
    p = base_dir / filename

    if not p.exists():
        raise FileNotFoundError(
            f"{p} not found. Generate it from your Terraform folder with:\n"
            f"terraform output -json > ../python/{filename}"
        )

    data = json.loads(p.read_text(encoding="utf-8"))
    return {k: v["value"] for k, v in data.items()}


def check_s3_public_access(bucket_name: str) -> List[str]:
    """
    Checks S3 Public Access Block configuration.
    Flags as HIGH if any Public Access Block settings are disabled or missing.
    """
    s3 = boto3.client("s3")
    findings: List[str] = []

    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        cfg = resp["PublicAccessBlockConfiguration"]

        # If any of these are False, public exposure risk increases
        disabled = [k for k, v in cfg.items() if v is False]

        if disabled:
            findings.append(
                f"[{HIGH}] S3 bucket '{bucket_name}' has Public Access Block settings disabled: "
                f"{', '.join(disabled)}"
            )
        else:
            findings.append(f"[{LOW}] S3 bucket '{bucket_name}' has Public Access Block fully enabled.")

    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        findings.append(f"[{HIGH}] S3 bucket '{bucket_name}' has NO Public Access Block configuration set.")

    except Exception as e:
        findings.append(f"[{MEDIUM}] ERROR checking S3 bucket '{bucket_name}': {e}")

    return findings


def check_security_group_rules(security_group_id: str) -> List[str]:
    """
    Reads inbound rules for the security group and flags 0.0.0.0/0 exposure.
    Flags SSH (22) exposure as HIGH, other 0.0.0.0/0 exposure as MEDIUM by default.
    """
    ec2 = boto3.client("ec2")
    findings: List[str] = []

    resp = ec2.describe_security_groups(GroupIds=[security_group_id])
    sg = resp["SecurityGroups"][0]
    perms = sg.get("IpPermissions", [])

    risky_found = False

    for perm in perms:
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        # Some rules (like ICMP) may not have ports
        # We'll still treat 0.0.0.0/0 as noteworthy.
        ip_ranges = perm.get("IpRanges", [])
        for r in ip_ranges:
            cidr = r.get("CidrIp")
            if cidr == "0.0.0.0/0":
                risky_found = True

                # Basic severity logic:
                # SSH open to world is HIGH
                if from_port == 22 or to_port == 22:
                    sev = HIGH
                    note = "SSH exposure"
                else:
                    sev = MEDIUM
                    note = "Inbound open to the internet"

                findings.append(
                    f"[{sev}] Security Group '{security_group_id}' allows inbound from {cidr} "
                    f"on ports {from_port}-{to_port} ({note})."
                )

    if not risky_found:
        findings.append(f"[{LOW}] Security Group '{security_group_id}' has no 0.0.0.0/0 inbound rules.")

    return findings


def check_iam_role_policies(role_name: str) -> List[str]:
    """
    Lists attached managed policies for a role and flags obvious over-permissive patterns:
    Effect=Allow AND Action includes "*" AND Resource includes "*"
    """
    iam = boto3.client("iam")
    findings: List[str] = []

    try:
        attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
        if not attached:
            findings.append(f"[{LOW}] IAM role '{role_name}' has no attached managed policies.")
            return findings

        flagged_any = False

        for pol in attached:
            pol_arn = pol["PolicyArn"]

            pol_meta = iam.get_policy(PolicyArn=pol_arn)["Policy"]
            version_id = pol_meta["DefaultVersionId"]
            pol_doc = iam.get_policy_version(PolicyArn=pol_arn, VersionId=version_id)["PolicyVersion"]["Document"]

            statements = pol_doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            over_permissive = False
            for st in statements:
                effect = st.get("Effect", "Allow")
                action = st.get("Action")
                resource = st.get("Resource")

                action_star = action == "*" or (isinstance(action, list) and "*" in action)
                resource_star = resource == "*" or (isinstance(resource, list) and "*" in resource)

                if effect == "Allow" and action_star and resource_star:
                    over_permissive = True
                    break

            if over_permissive:
                flagged_any = True
                findings.append(
                    f"[{HIGH}] IAM role '{role_name}' has an over-permissive policy attached: {pol_arn} "
                    f"(Allow '*' on '*')."
                )
            else:
                findings.append(
                    f"[{LOW}] IAM role '{role_name}' attached policy not obviously over-permissive: {pol_arn}"
                )

        if not flagged_any:
            # Not required, but nice to summarize
            findings.append(f"[{LOW}] No obvious wildcard-wildcard IAM policies detected for role '{role_name}'.")

    except Exception as e:
        findings.append(f"[{MEDIUM}] ERROR checking IAM role '{role_name}': {e}")

    return findings


def summarize_findings(all_findings: List[str]) -> None:
    total = len(all_findings)
    high = sum(1 for f in all_findings if f.startswith(f"[{HIGH}]"))
    medium = sum(1 for f in all_findings if f.startswith(f"[{MEDIUM}]"))
    low = sum(1 for f in all_findings if f.startswith(f"[{LOW}]"))

    print("\n=== Summary ===")
    print(f"Total findings: {total}")
    print(f"HIGH: {high} | MEDIUM: {medium} | LOW: {low}")


def export_findings_json(all_findings: List[str], filename: str = "findings.json") -> None:
    """
    Writes findings to a JSON file in the same folder as this script.
    """
    base_dir = Path(__file__).parent
    out_path = base_dir / filename
    out_path.write_text(json.dumps(all_findings, indent=2), encoding="utf-8")


def main() -> None:
    outputs = load_tf_outputs()

    # These output keys must match your Terraform outputs file.
    # If your keys differ, update them here.
    bucket = outputs.get("s3_bucket_name")
    sg_id = outputs.get("security_group_id")
    role = outputs.get("iam_role_name")

    print("\n=== Cloud Security Audit Findings ===\n")

    all_findings: List[str] = []

    if bucket:
        all_findings.extend(check_s3_public_access(bucket))
    else:
        all_findings.append(f"[{MEDIUM}] Missing Terraform output: s3_bucket_name")

    if sg_id:
        all_findings.extend(check_security_group_rules(sg_id))
    else:
        all_findings.append(f"[{MEDIUM}] Missing Terraform output: security_group_id")

    if role:
        all_findings.extend(check_iam_role_policies(role))
    else:
        all_findings.append(f"[{MEDIUM}] Missing Terraform output: iam_role_name")

    # Print findings
    for f in all_findings:
        print(f"- {f}")

    summarize_findings(all_findings)

    # Optional: export findings for paper notes / later analysis
    export_findings_json(all_findings, filename="findings.json")
    print("\nFindings exported to findings.json")

    print("\n=== End ===\n")


if __name__ == "__main__":
    main()
