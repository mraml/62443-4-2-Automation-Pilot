#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OSCAL Assessment Results Generator for Ansible

Description:
This script automates the creation of an OSCAL Assessment Results document by parsing
the JSON output of an Ansible playbook run in check mode. It correlates Ansible task
results with security controls via tags and generates a formal, auditable compliance report.

Prerequisites:
1. An Ansible playbook with tasks tagged with the corresponding OSCAL control IDs.
   Example:
     - name: "CR-7.7 | Ensure minimal packages are installed"
       ansible.builtin.dnf:
         name: [cockpit]
         state: absent
       tags:
         - CR-7.7

2. An OSCAL Assessment Plan (in JSON format) that defines the scope of the assessment.

3. An Ansible check mode report (in JSON format), generated using the following command:
   ansible-playbook <your-playbook.yaml> --check -o > ansible-check-report.json
"""

import json
import argparse
import uuid
import logging
from datetime import datetime, timezone

# --- Configuration ---
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

# --- Helper Functions ---

def load_json_file(file_path):
    """Safely loads a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in file: {file_path}")
        return None

def initialize_assessment_results(assessment_plan, report_filename):
    """Creates the basic structure for the OSCAL Assessment Results document."""
    timestamp = datetime.now(timezone.utc).isoformat()
    ap_metadata = assessment_plan.get("assessment-plan", {}).get("metadata", {})

    return {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"Assessment Results for {ap_metadata.get('title', 'Unknown Plan')}",
                "last-modified": timestamp,
                "version": "1.0.0",
                "oscal-version": "1.0.0",
                "roles": ap_metadata.get("roles", []),
                "parties": ap_metadata.get("parties", []),
                "responsible-parties": ap_metadata.get("responsible-parties", [])
            },
            "import-ap": {
                "href": "#" + assessment_plan.get("assessment-plan", {}).get("uuid")
            },
            "results": [],
            "back-matter": {
                "resources": [
                    {
                        "uuid": str(uuid.uuid4()),
                        "description": "The Ansible check mode report used as evidence for this assessment.",
                        "rlinks": [
                            {
                                "href": report_filename,
                                "media-type": "application/json"
                            }
                        ]
                    }
                ]
            }
        }
    }

# --- Core Logic ---

def process_ansible_report(ansible_report, assessment_plan, report_filename):
    """
    Parses the Ansible report and generates OSCAL findings.
    """
    if not ansible_report or not assessment_plan:
        return None

    oscal_results = initialize_assessment_results(assessment_plan, report_filename)
    evidence_resource_uuid = oscal_results["assessment-results"]["back-matter"]["resources"][0]["uuid"]

    # Assume a single result for this automated run
    result_uuid = str(uuid.uuid4())
    result = {
        "uuid": result_uuid,
        "title": "Automated Assessment from Ansible Check Report",
        "start": datetime.now(timezone.utc).isoformat(),
        "findings": [],
        "observations": [],
        "risks": []
    }

    try:
        tasks = ansible_report.get("plays", [])[0].get("tasks", [])
    except IndexError:
        logging.error("Ansible report does not contain any plays or tasks.")
        return None

    for task in tasks:
        task_details = task.get("task", {})
        control_ids = task_details.get("tags", [])

        if not control_ids:
            continue  # Skip tasks without control ID tags

        control_id = control_ids[0]
        task_name = task_details.get("name", f"Task for {control_id}")
        is_compliant = not task.get("changed", False)

        # Create Observation
        observation_uuid = str(uuid.uuid4())
        observation = {
            "uuid": observation_uuid,
            "title": f"Observation for {control_id}",
            "description": f"Automated check performed by Ansible task: '{task_name}'",
            "methods": ["TEST"],
            "relevant-evidence": [
                {
                    "href": f"#{evidence_resource_uuid}",
                    "description": f"Ansible check mode report for task related to {control_id}."
                }
            ]
        }
        result["observations"].append(observation)

        # Create Finding
        finding_uuid = str(uuid.uuid4())
        finding = {
            "uuid": finding_uuid,
            "title": f"Finding for {control_id}",
            "description": f"Control is satisfied and correctly implemented." if is_compliant else f"Control is NOT satisfied. The system configuration has drifted from the baseline.",
            "related-observations": [{"observation-uuid": observation_uuid}]
        }
        result["findings"].append(finding)

        # Create Risk and POA&M link if not compliant
        if not is_compliant:
            risk_uuid = str(uuid.uuid4())
            poam_uuid = str(uuid.uuid4())
            risk = {
                "uuid": risk_uuid,
                "title": f"Configuration Drift Detected for {control_id}",
                "description": f"The Ansible check mode report indicated a 'changed' state for the task implementing {control_id}, meaning the system is not compliant with its intended configuration.",
                "statement": f"The system's implementation of {control_id} is non-compliant.",
                "status": "open",
                "related-risk-responses": [{"risk-response-uuid": poam_uuid}]
            }
            result["risks"].append(risk)
            
            # In a real system, you would link to a full POA&M file.
            # Here, we add a placeholder resource.
            poam_resource = {
                "uuid": poam_uuid,
                "title": f"POA&M for {control_id}",
                "description": f"This is a reference to a separate POA&M file that would track the remediation for the finding related to {control_id}."
            }
            oscal_results["assessment-results"]["back-matter"]["resources"].append(poam_resource)


    result["end"] = datetime.now(timezone.utc).isoformat()
    oscal_results["assessment-results"]["results"].append(result)
    return oscal_results

# --- Main Execution ---

def main():
    """Main function to orchestrate the script."""
    parser = argparse.ArgumentParser(description="Generate OSCAL Assessment Results from an Ansible Check Report.")
    parser.add_argument("--report", required=True, help="Path to the Ansible check mode report in JSON format.")
    parser.add_argument("--plan", required=True, help="Path to the OSCAL Assessment Plan in JSON format.")
    parser.add_argument("--output", required=True, help="Path to write the output OSCAL Assessment Results JSON file.")
    args = parser.parse_args()

    logging.info(f"Loading Ansible report from: {args.report}")
    ansible_report = load_json_file(args.report)

    logging.info(f"Loading OSCAL Assessment Plan from: {args.plan}")
    assessment_plan = load_json_file(args.plan)

    if ansible_report and assessment_plan:
        logging.info("Processing report and generating OSCAL Assessment Results...")
        oscal_results = process_ansible_report(ansible_report, assessment_plan, args.report)

        if oscal_results:
            try:
                with open(args.output, 'w') as f:
                    json.dump(oscal_results, f, indent=2)
                logging.info(f"Successfully generated OSCAL Assessment Results at: {args.output}")
            except IOError as e:
                logging.error(f"Could not write to output file {args.output}: {e}")
        else:
            logging.error("Failed to generate OSCAL Assessment Results.")
    else:
        logging.error("Aborting due to errors loading input files.")

if __name__ == "__main__":
    main()
