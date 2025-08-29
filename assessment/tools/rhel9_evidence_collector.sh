#!/bin/bash

# rhel9_evidence_collector.sh
#
# This script orchestrates the evidence collection process for a RHEL 9 host.
# It runs the comprehensive Ansible hardening playbook in check mode, saves the
# raw JSON output, and then calls the Python parser script to generate the final,
# Gamera-compatible evidence file.
#
# Usage: ./generate_rhel9_evidence.sh <target_host_in_inventory>

set -e

# --- Configuration ---
TARGET_HOST=$1
PLAYBOOK_PATH="./rhel9_iac_comprehensive.yaml" #verify name
INVENTORY_PATH="./production_inventory" # Assumes you have an Ansible inventory file
PARSER_SCRIPT_PATH="./rhel9_evidence_parser.py"  #verify name
RAW_REPORT_FILE="/tmp/ansible_raw_report.json" 
FINAL_EVIDENCE_FILE="rhel9_runtime_evidence.json" 

# --- Validation ---
if [ -z "$TARGET_HOST" ]; then
    echo "Error: Target host must be specified."
    echo "Usage: $0 <target_host_in_inventory>"
    exit 1
fi

if [ ! -f "$PLAYBOOK_PATH" ]; then
    echo "Error: Playbook not found at '$PLAYBOOK_PATH'"
    exit 1
fi

if [ ! -f "$PARSER_SCRIPT_PATH" ]; then
    echo "Error: Parser script not found at '$PARSER_SCRIPT_PATH'"
    exit 1
fi


# --- Step 1: Run Ansible Playbook in Check Mode ---
echo "Running Ansible playbook in check mode against host: $TARGET_HOST..."

# The '-o' flag creates a condensed, one-line JSON output that's easier to parse.
ansible-playbook -i "$INVENTORY_PATH" "$PLAYBOOK_PATH" --limit "$TARGET_HOST" --check --diff -o > "$RAW_REPORT_FILE"

echo "Ansible check complete. Raw report saved to '$RAW_REPORT_FILE'."


# --- Step 2: Parse the Report and Generate Final Evidence ---
echo "Parsing raw report and generating final Gamera-compatible evidence file..."

# Pass the target host to the script via an environment variable
export TARGET_HOST
python3 "$PARSER_SCRIPT_PATH" "$RAW_REPORT_FILE"

echo "-----------------------------------------------------"
echo "Process complete."
echo "Final evidence file saved to: $FINAL_EVIDENCE_FILE"
echo "-----------------------------------------------------"

# Clean up the raw report file
rm "$RAW_REPORT_FILE"
