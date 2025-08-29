#!/usr/bin/env python3

# rhel9_evidence_parser.py
#
# This script parses the JSON output of an `ansible-playbook --check` run and
# translates it into a structured JSON evidence file that can be consumed by
# a tool like Gamera.
#
# It correlates Ansible task results with compliance control IDs via tags and
# determines a pass/fail status based on whether a task reported a change.

import json
import datetime
import sys
import os

def parse_ansible_report(report_path):
    """Parses the Ansible JSON report and extracts results for tagged tasks."""
    
    if not os.path.exists(report_path):
        print(f"Error: Ansible report file not found at '{report_path}'", file=sys.stderr)
        return None

    with open(report_path, 'r') as f:
        try:
            report_data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in Ansible report file '{report_path}'. {e}", file=sys.stderr)
            return None
            
    check_results = []
    
    # Ansible's JSON output structure can be complex. We need to iterate through plays and tasks.
    if 'plays' not in report_data or not report_data['plays']:
        print("Error: No plays found in the Ansible report.", file=sys.stderr)
        return None

    for play in report_data['plays']:
        if 'tasks' not in play:
            continue
        for task_result in play['tasks']:
            task = task_result.get('task', {})
            # We only care about tasks that have been tagged with a control ID
            tags = task.get('tags', [])
            if not tags:
                continue

            # Assuming the first tag is the control ID
            control_id = tags[0]
            
            # In check mode, 'changed: true' means the system is not compliant (a change *would* be made).
            is_pass = not task_result.get('changed', False)
            
            details = f"Task '{task.get('name', 'N/A')}': "
            if is_pass:
                details += "Configuration is compliant."
            else:
                details += "Configuration drift detected. "
                # Include diff if available
                if 'diff' in task_result:
                    details += "Diff: " + json.dumps(task_result['diff'])

            check_results.append({
                "check_id": control_id,
                "pass": is_pass,
                "details": details
            })

    return check_results

def main():
    """Main function to generate the Gamera-compatible evidence report."""

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_ansible_report.json>", file=sys.stderr)
        sys.exit(1)

    ansible_report_file = sys.argv[1]
    
    print(f"Parsing Ansible report from '{ansible_report_file}'...")

    check_results = parse_ansible_report(ansible_report_file)

    if check_results is None:
        sys.exit(1)

    # In a real environment, you would get the FQDN from the inventory or a fact
    hostname = os.environ.get("TARGET_HOST", "rhel9-host.example.com")

    evidence_report = {
        "evidence_type": "ansible_check_report",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hostname": hostname,
        "evidence_collector_version": "1.0.0",
        "checks": check_results
    }

    output_filename = "rhel9_runtime_evidence.json"
    with open(output_filename, "w") as f:
        json.dump(evidence_report, f, indent=2)

    print(f"Evidence collection complete. Gamera-compatible report saved to '{output_filename}'.")

if __name__ == "__main__":
    main()
