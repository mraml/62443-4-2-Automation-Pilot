package main

// Gamera Mapping for OpenShift 4 aligned with ISA/IEC 62443-4-2 SL-4
// This file defines the comprehensive, line-by-line evidence required to
// satisfy each security control for a production-ready assessment.
mapping: {
	controls: {
		// --- FR 1: Identification & Authentication Control ---
		"cr-1.1_re.2": { // Human User MFA
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies the cluster OAuth custom resource is configured to use a central OIDC identity provider that enforces MFA."
				constraints: { check_id: "oauth_oidc_mfa_configured", pass: true }
			}]
		},
		"cr-1.2_re.1": { // Unique Software/Device ID
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that all ServiceAccounts have unique, system-assigned UIDs."
				constraints: { check_id: "serviceaccount_uids_unique", pass: true }
			}]
		},
		"cr-1.5_re.1": { // Hardware Security for Authenticators
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that etcd encryption is enabled, leveraging the underlying host's TPM for key protection if configured."
				constraints: { check_id: "etcd_encryption_enabled", pass: true }
			}]
		},
		"cr-1.8": { // PKI Certificates
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies the cluster-wide proxy and API server are configured with trusted CA bundles."
				constraints: { check_id: "pki_trusted_cas_configured", pass: true }
			}]
		},
		"cr-1.11": { // Unsuccessful Login Attempts
			evidence: [{
				type:        "external_evidence"
				description: "Requires evidence from the external IdP (e.g., a configuration export or screenshot) showing that account lockout policies are enabled."
				constraints: { check_id: "idp_account_lockout_policy", pass: true }
			}]
		},
		"cr-1.12": { // System Use Notification
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies the Console custom resource has a login notification banner configured."
				constraints: { check_id: "console_banner_configured", pass: true }
			}]
		},

		// --- FR 2: Use Control ---
		"cr-2.1_re.4": { // Authorization Enforcement & Dual Approval
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that a ClusterRoleBinding exists that restricts the cluster-admin role to a specific, non-default group."
				constraints: { check_id: "cluster_admin_restricted", pass: true }
			}]
		},
		"cr-2.5": { // Session Lock
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies the Console custom resource has a non-zero inactivity timeout configured."
				constraints: { check_id: "console_inactivity_timeout_set", pass: true }
			}]
		},
		"cr-2.8": { // Auditable Events
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies the APIServer custom resource has an audit policy profile set to 'Default' or stricter."
				constraints: { check_id: "audit_policy_profile_set", pass: true }
			}]
		},
		"cr-2.11_re.2": { // Time Synchronization & Integrity
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that MachineConfig objects are in place to configure chronyd on all nodes to point to a trusted NTP source."
				constraints: { check_id: "node_ntp_configured", pass: true }
			}]
		},
		"sar-2.4_re.1": { // Mobile Code & Authenticity Check
			description: "This control is satisfied by software supply chain evidence for every critical application container image."
			evidence: [
				{ type: "sbom", description: "A CycloneDX SBOM must be present." },
				{
					type:        "vulnerability_scan"
					description: "Scan report must show no CRITICAL or HIGH severity vulnerabilities."
					constraints: { max_critical_vulnerabilities: 0, max_high_vulnerabilities: 0 }
				},
				{
					type:        "slsa_provenance"
					description: "An in-toto attestation must prove a trusted build at SLSA Level 3 or higher."
					constraints: { min_slsa_level: 3 }
				},
			]
		},

		// --- FR 3: System Integrity ---
		"cr-3.1_re.1": { // Communication Integrity & Auth
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies the APIServer custom resource is configured with a 'Modern' TLS security profile."
				constraints: { check_id: "apiserver_tls_modern", pass: true }
			}]
		},
		"cr-3.4_re.2": { // Software/Info Integrity & Notification
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that a FileIntegrity object is configured to monitor cluster nodes and alert on changes."
				constraints: { check_id: "file_integrity_operator_configured", pass: true }
			}]
		},
		"cr-3.9_re.1": { // Protection of Audit Info (Write-Once Media)
			evidence: [{
				type:        "external_evidence"
				description: "Requires evidence from the SIEM (e.g., a configuration export) showing that the log storage is WORM-compliant."
				constraints: { check_id: "siem_storage_worm_compliant", pass: true }
			}]
		},

		// --- FR 4: Data Confidentiality ---
		"cr-4.1": { // Information Confidentiality
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that etcd encryption is enabled in the APIServer custom resource."
				constraints: { check_id: "etcd_encryption_enabled", pass: true }
			}]
		},
		"cr-4.3": { // Use of Cryptography
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that MachineConfig objects are in place to enable FIPS mode on all cluster nodes."
				constraints: { check_id: "fips_mode_enabled", pass: true }
			}]
		},

		// --- FR 5: Restricted Data Flow ---
		"cr-5.1": {
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that a 'default-deny-ingress' NetworkPolicy exists in all critical application namespaces."
				constraints: { check_id: "default_deny_network_policy_exists", pass: true }
			}]
		},

		// --- FR 6: Timely Response to Events ---
		"cr-6.2": {
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that the ClusterLogForwarder custom resource is configured to send all log types to an external SIEM."
				constraints: { check_id: "log_forwarding_configured", pass: true }
			}]
		},

		// --- FR 7: Resource Availability ---
		"cr-7.1": {
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that ResourceQuota and LimitRange objects exist in all critical application namespaces."
				constraints: { check_id: "resource_quotas_exist", pass: true }
			}]
		},
		"cr-7.2": {
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that critical cluster operators have guaranteed resource requests and limits set."
				constraints: { check_id: "critical_operator_resources_set", pass: true }
			}]
		},
		"cr-7.7": {
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that non-essential cluster operators are disabled via the ClusterVersion custom resource."
				constraints: { check_id: "least_functionality_operators_disabled", pass: true }
			}]
		},
	}
}

