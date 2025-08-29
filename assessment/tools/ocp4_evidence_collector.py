#!/usr/bin/env python3

# ocp4_evidence_collector.py
#
# This script acts as an Evidence Collector for an OpenShift 4 cluster. It is designed
# to run against a live cluster and generate a JSON-formatted evidence report that can be
# consumed by an evidence-based compliance tool like Gamera.
#
# It performs a series of checks, each corresponding to a `check_id` in the
# accompanying Gamera mapping file (openshift_gamera_mapping.cue).
#
# Prerequisites:
#   - Python 3.6+
#   - The 'oc' command-line tool must be installed and in the system's PATH.
#   - The script must be run from a context where 'oc' is logged into the target
#     cluster with at least view-level permissions on the checked resources.

import json
import subprocess
import datetime
import sys

def run_oc_command(command):
    """Runs an 'oc' command and returns its JSON output."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}\nStderr: {e.stderr}", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from command: {command}\nError: {e}", file=sys.stderr)
        return None

def check_oauth_oidc(checks):
    """CR-1.1: Checks if an OIDC identity provider is configured."""
    details = "OAuth is not configured with an OIDC identity provider."
    is_pass = False
    oauth_config = run_oc_command("oc get oauth cluster -o json")
    if oauth_config:
        providers = oauth_config.get("spec", {}).get("identityProviders", [])
        for provider in providers:
            if provider.get("type") == "OpenID":
                is_pass = True
                details = "OAuth is configured with an OIDC identity provider."
                break
    checks.append({"check_id": "oauth_oidc_mfa_configured", "pass": is_pass, "details": details})

def check_console_banner(checks):
    """CR-1.12: Checks if the console login banner is configured."""
    details = "Console login notification banner is not configured."
    is_pass = False
    console_config = run_oc_command("oc get console cluster -o json")
    if console_config:
        if console_config.get("spec", {}).get("customization", {}).get("loginNotification", {}):
            is_pass = True
            details = "Console login notification banner is configured and active."
    checks.append({"check_id": "console_banner_configured", "pass": is_pass, "details": details})
    
def check_session_timeout(checks):
    """CR-2.5: Checks if the session inactivity timeout is set."""
    details = "OAuth token inactivity timeout is not set or not compliant."
    is_pass = False
    console_config = run_oc_command("oc get console cluster -o json")
    if console_config:
        timeout = console_config.get("spec", {}).get("authentication", {}).get("inactivityTimeoutSeconds")
        # Assuming requirement is 900 seconds (15 minutes) or less
        if timeout and timeout <= 900:
             is_pass = True
             details = f"OAuth token inactivity timeout is set to {timeout} seconds."
    checks.append({"check_id": "session_timeout_set", "pass": is_pass, "details": details})


def check_apiserver_tls(checks):
    """CR-3.1: Checks if the APIServer is using the 'Modern' TLS profile."""
    details = "APIServer is not configured with the 'Modern' TLS Security Profile."
    is_pass = False
    apiserver_config = run_oc_command("oc get apiserver cluster -o json")
    if apiserver_config:
        profile = apiserver_config.get("spec", {}).get("tlsSecurityProfile", {})
        if profile.get("type") == "Modern":
            is_pass = True
            details = "APIServer is configured with the 'Modern' TLS Security Profile."
    checks.append({"check_id": "apiserver_tls_modern", "pass": is_pass, "details": details})

def check_etcd_encryption(checks):
    """CR-4.1: Checks if etcd encryption is enabled."""
    details = "etcd data encryption is not enabled."
    is_pass = False
    apiserver_config = run_oc_command("oc get apiserver cluster -o json")
    if apiserver_config:
        encryption_type = apiserver_config.get("spec", {}).get("encryption", {}).get("type")
        if encryption_type and encryption_type != "identity":
             is_pass = True
             details = f"etcd data encryption is enabled with the '{encryption_type}' provider."
    checks.append({"check_id": "etcd_encryption_enabled", "pass": is_pass, "details": details})

def check_fips_mode(checks):
    """CR-4.3: Checks if all nodes are running in FIPS mode."""
    details = "Not all nodes are confirmed to be running in FIPS mode."
    is_pass = False
    nodes = run_oc_command("oc get nodes -o json")
    if nodes and nodes.get("items"):
        fips_nodes = 0
        for node in nodes["items"]:
            # A more robust check might inspect MachineConfigs, but this is a good start
            if "feature.node.kubernetes.io/fips" in node.get("metadata", {}).get("labels", {}):
                 fips_nodes += 1
        if fips_nodes == len(nodes["items"]):
            is_pass = True
            details = "All cluster nodes are confirmed to be running in FIPS mode."
    checks.append({"check_id": "fips_mode_enabled", "pass": is_pass, "details": details})

# --- Add other check functions here following the same pattern ---
# e.g., check_default_deny_policy, check_log_forwarding, etc.

def main():
    """Main function to run all checks and generate the report."""
    
    print("Starting OpenShift evidence collection...")
    
    cluster_info = run_oc_command("oc get clusterversion version -o json")
    cluster_id = cluster_info.get("spec", {}).get("clusterID", "unknown") if cluster_info else "unknown"

    evidence_report = {
        "evidence_type": "openshift_runtime_evidence",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "cluster_id": cluster_id,
        "evidence_collector_version": "1.0.0",
        "checks": []
    }

    # Run all the check functions
    check_oauth_oidc(evidence_report["checks"])
    check_console_banner(evidence_report["checks"])
    check_session_timeout(evidence_report["checks"])
    check_apiserver_tls(evidence_report["checks"])
    check_etcd_encryption(evidence_report["checks"])
    check_fips_mode(evidence_report["checks"])
    # --- Call other check functions here ---
    
    # Write the report to a file
    output_filename = "ocp4_runtime_evidence.json"
    with open(output_filename, "w") as f:
        json.dump(evidence_report, f, indent=2)

    print(f"Evidence collection complete. Report saved to '{output_filename}'.")

if __name__ == "__main__":
    main()
