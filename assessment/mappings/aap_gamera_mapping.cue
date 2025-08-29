package main

// Gamera Mapping for Ansible Automation Platform (AAP) 2.5+ aligned with ISA/IEC 62443-4-2 SL-4.
// This file defines the comprehensive, line-by-line evidence required to satisfy
// each security control for a production-ready, evidence-based assessment.
// It requires two primary evidence types: one for the AAP application's runtime state (aap_runtime_evidence)
// and one for the underlying RHEL 9 host's configuration (ansible_check_report).
mapping: {
	controls: {
		// --- FR 1: Identification & Authentication Control ---
		"cr-1.1_re.2": { // Human User MFA
			evidence: [{
				type:        "external_evidence"
				description: "Requires evidence from the central IdP (e.g., a configuration export) showing that MFA is enforced for the AAP user group."
				constraints: { check_id: "idp_aap_mfa_policy", pass: true }
			}]
		},
		"cr-1.5": { // Authenticator Management
			evidence: [{
				type:        "aap_runtime_evidence"
				description: "Verifies that AAP is configured to use an external credential vault (e.g., HashiCorp Vault) and that no static credentials are used."
				constraints: { check_id: "external_credential_vault_configured", pass: true }
			}]
		},

		// --- FR 2: Use Control ---
		"cr-2.1_re.2": { // Authorization Enforcement (Permissions to Roles)
			evidence: [{
				type:        "aap_runtime_evidence"
				description: "Verifies that AAP RBAC is configured, with specific teams and roles for operators and administrators."
				constraints: { check_id: "aap_rbac_configured", pass: true }
			}]
		},
		"cr-2.1_re.4": { // Dual Approval
			evidence: [{
				type:        "aap_runtime_evidence"
				description: "Verifies that critical job templates are part of a workflow that includes a mandatory approval gate."
				constraints: { check_id: "workflow_approval_gate_exists", pass: true }
			}]
		},
		"cr-2.5": { // Session Lock
			evidence: [{
				type:        "aap_runtime_evidence"
				description: "Verifies that session timeout settings within the AAP application are configured to an approved value."
				constraints: { check_id: "aap_session_timeout_set", pass: true }
			}]
		},
		"cr-2.8": { // Auditable Events
			evidence: [{
				type:        "aap_runtime_evidence"
				description: "Verifies that AAP's activity stream logging is enabled and capturing all job and user events."
				constraints: { check_id: "aap_activity_stream_enabled", pass: true }
			}]
		},

		// --- FR 3: System Integrity ---
		"cr-3.9": { // Protection of Audit Information
			evidence: [{
				type:        "aap_runtime_evidence"
				description: "Verifies that access to the AAP activity stream is restricted to authorized administrative roles."
				constraints: { check_id: "aap_audit_log_rbac_protected", pass: true }
			}]
		},

		// --- FR 4: Data Confidentiality ---
		"cr-4.1": { // Information Confidentiality
			evidence: [{
				type:        "aap_runtime_evidence"
				description: "Verifies that all credential objects within AAP are configured to use an external, encrypted vault."
				constraints: { check_id: "external_credential_vault_configured", pass: true }
			}]
		},
		"cr-4.3": { // Use of Cryptography (Host)
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies the underlying RHEL 9 host is operating in FIPS mode."
				constraints: { check_id: "cr-4.3", changed: false }
			}]
		},

		// --- FR 5: Restricted Data Flow (Host) ---
		"cr-5.1": {
			evidence: [{
				type:        "ansible_check_report"
				description: "Verifies that firewalld on the host is active and configured with a default-deny policy."
				constraints: { check_id: "cr-5.1", changed: false }
			}]
		},

		// --- FR 6: Timely Response to Events ---
		"cr-6.2": { // Continuous Monitoring
			evidence: [{
				type:        "aap_runtime_evidence"
				description: "Verifies that AAP is configured to forward its activity stream and system logs to a central SIEM."
				constraints: { check_id: "aap_log_forwarding_configured", pass: true }
			}, {
				type:        "ansible_check_report"
				description: "Verifies the underlying RHEL 9 host is configured to forward its logs to the same central SIEM."
				constraints: { check_id: "cr-6.2", changed: false }
			}]
		},

		// --- FR 7: Resource Availability ---
		"cr-7.2": { // Resource Management
			evidence: [{
				type:        "aap_runtime_evidence"
				description: "Verifies that job slicing and resource limits are configured within AAP to prevent any single job from consuming excessive resources."
				constraints: { check_id: "aap_job_resource_limits_set", pass: true }
			}, {
				type:        "ansible_check_report"
				description: "Verifies that systemd slices are configured on the host to limit resources for the AAP services."
				constraints: { check_id: "cr-7.2", changed: false }
			}]
		},
	}
}
