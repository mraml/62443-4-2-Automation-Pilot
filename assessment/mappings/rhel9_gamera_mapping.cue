package main

// Gamera Mapping for RHEL 9 aligned with ISA/IEC 62443-4-2 SL-4
// This file defines the comprehensive, line-by-line evidence required to
// satisfy each security control for a production-ready assessment.
mapping: {
	controls: {
		// --- FR 1: Identification & Authentication Control ---
		"cr-1.1_re.2": { // Human User MFA
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that the SSSD and PAM configurations are set to require MFA via the central identity provider."
				constraints: { check_id: "cr-1.1_re.2", changed: false }
			}]
		},
		"cr-1.5_re.1": { // Hardware Security for Authenticators
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that LUKS disk encryption is active and bound to the hardware TPM."
				constraints: { check_id: "cr-1.5_re.1", changed: false }
			}]
		},
		"cr-1.7_re.2": { // Strength of Password-based Authentication
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that /etc/security/pwquality.conf is configured to enforce strong password complexity, history, and lifetime policies for local accounts."
				constraints: { check_id: "cr-1.7_re.2", changed: false }
			}]
		},
		"cr-1.11": { // Unsuccessful Login Attempts
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that the pam_faillock module is configured to lock accounts after a specified number of failed attempts."
				constraints: { check_id: "cr-1.11", changed: false }
			}]
		},
		"cr-1.12": { // System Use Notification
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that /etc/motd and /etc/issue are populated with the approved system use banner."
				constraints: { check_id: "cr-1.12", changed: false }
			}]
		},

		// --- FR 2: Use Control ---
		"cr-2.1_re.2": { // Authorization Enforcement (Permissions to Roles)
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies SELinux is in enforcing mode and sudoers rules are configured to grant privileges only to authorized groups."
				constraints: { check_id: "cr-2.1_re.2", changed: false }
			}]
		},
		"cr-2.5": { // Session Lock
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that /etc/ssh/sshd_config is configured to terminate idle sessions after a defined timeout."
				constraints: { check_id: "cr-2.5", changed: false }
			}]
		},
		"cr-2.8": { // Auditable Events
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that the auditd service is active and a comprehensive rule set is deployed."
				constraints: { check_id: "cr-2.8", changed: false }
			}]
		},
		"cr-2.11_re.2": { // Time Synchronization & Integrity
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that chronyd is configured to use multiple, trusted internal NTP sources."
				constraints: { check_id: "cr-2.11_re.2", changed: false }
			}]
		},
		"hdr-2.4_re.1": { // Mobile Code & Authenticity Check
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that temporary directories are mounted with 'noexec' and that DNF is configured to perform GPG signature checks on all packages."
				constraints: { check_id: "hdr-2.4_re.1", changed: false }
			}]
		},

		// --- FR 3: System Integrity ---
		"cr-3.1_re.1": { // Communication Integrity & Auth
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that the system-wide crypto policy is set to 'FIPS' or 'FUTURE'."
				constraints: { check_id: "cr-3.1_re.1", changed: false }
			}]
		},
		"cr-3.4_re.2": { // Software/Info Integrity & Notification
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that AIDE is installed and a cron job is configured to run regular integrity checks and report violations."
				constraints: { check_id: "cr-3.4_re.2", changed: false }
			}]
		},
		"hdr-3.10_re.1": { // Update Authenticity and Integrity
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that DNF is configured to perform GPG signature checks on all packages."
				constraints: { check_id: "hdr-3.10_re.1", changed: false }
			}]
		},

		// --- FR 4: Data Confidentiality ---
		"cr-4.1": { // Information Confidentiality
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that all persistent data volumes are using LUKS encryption."
				constraints: { check_id: "cr-4.1", changed: false }
			}]
		},
		"cr-4.3": { // Use of Cryptography
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that the system is operating in FIPS mode."
				constraints: { check_id: "cr-4.3", changed: false }
			}]
		},

		// --- FR 5: Restricted Data Flow ---
		"cr-5.1": {
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that firewalld is active and configured with a default-deny policy, only allowing explicitly permitted services."
				constraints: { check_id: "cr-5.1", changed: false }
			}]
		},

		// --- FR 6: Timely Response to Events ---
		"cr-6.2": { // Continuous Monitoring
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that rsyslog or auditd are configured to forward all security-relevant logs to a central SIEM."
				constraints: { check_id: "cr-6.2", changed: false }
			}]
		},

		// --- FR 7: Resource Availability ---
		"cr-7.1": {
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that secure kernel parameters (sysctl) are set to mitigate DoS attacks."
				constraints: { check_id: "cr-7.1", changed: false }
			}]
		},
		"cr-7.2": {
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that systemd slices and /etc/security/limits.conf are configured to enforce resource limits on services and users."
				constraints: { check_id: "cr-7.2", changed: false }
			}]
		},
		"cr-7.7": {
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that a list of unnecessary packages (e.g., cockpit, sendmail) are in the 'absent' state."
				constraints: { check_id: "cr-7.7", changed: false }
			}]
		},
	}
}
