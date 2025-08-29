package main

// Gamera Mapping for OpenShift 4 aligned with ISA/IEC 62443-4-2 SL-4
// This file defines the evidence required to satisfy each security control.
mapping: {
	controls: {
		// --- FR 1: Identification & Authentication Control ---
		"cr-1.1_re.2": { // Includes CR-1.1, RE.1, RE.2
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that the cluster OAuth is configured to use a central OIDC identity provider that enforces MFA."
				constraints: {
					check_id: "oauth_mfa_configured"
					pass:     true
				}
			}]
		},
		"cr-1.12": {
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies the Console custom resource has a login notification banner configured."
				constraints: {
					check_id: "console_banner_configured"
					pass:     true
				}
			}]
		},

		// --- FR 2: Use Control ---
		"cr-2.1_re.4": { // Includes CR-2.1 and all REs
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that a ClusterRoleBinding exists that restricts the cluster-admin role to a specific, non-default group."
				constraints: {
					check_id: "cluster_admin_restricted"
					pass:     true
				}
			}]
		},
		"sar-2.4_re.1": { // Mobile Code & Authenticity Check
			description: "This control is satisfied by a combination of software supply chain evidence for every critical application container image."
			evidence: [
				{
					type:        "sbom"
					description: "A CycloneDX SBOM must be present for the container image."
				},
				{
					type:        "vulnerability_scan"
					description: "A vulnerability scan report must be present and show no CRITICAL or HIGH severity vulnerabilities."
					constraints: {
						max_critical_vulnerabilities: 0
						max_high_vulnerabilities:   0
					}
				},
				{
					type:        "slsa_provenance"
					description: "An in-toto attestation must be present proving the image was built in a trusted pipeline at SLSA Level 3 or higher."
					constraints: {
						min_slsa_level: 3
					}
				},
			]
		},

		// --- FR 3: System Integrity ---
		"cr-3.1_re.1": {
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies the APIServer custom resource is configured with a 'Modern' TLS security profile."
				constraints: {
					check_id: "apiserver_tls_modern"
					pass:     true
				}
			}]
		},
		"cr-3.4_re.2": {
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that a FileIntegrity object is configured to monitor cluster nodes."
				constraints: {
					check_id: "file_integrity_operator_configured"
					pass:     true
				}
			}]
		},

		// --- FR 4: Data Confidentiality ---
		"cr-4.3": {
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that MachineConfig objects are in place to enable FIPS mode on all cluster nodes."
				constraints: {
					check_id: "fips_mode_enabled"
					pass:     true
				}
			}]
		},

		// --- FR 5: Restricted Data Flow ---
		"cr-5.1": {
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that a 'default-deny-ingress' NetworkPolicy exists in all critical application namespaces."
				constraints: {
					check_id: "default_deny_network_policy_exists"
					pass:     true
				}
			}]
		},

		// --- FR 6: Timely Response to Events ---
		"cr-6.2": {
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that the ClusterLogForwarder custom resource is configured to send all log types to an external SIEM."
				constraints: {
					check_id: "log_forwarding_configured"
					pass:     true
				}
			}]
		},

		// --- FR 7: Resource Availability ---
		"cr-7.1": {
			evidence: [{
				type:        "openshift_runtime_evidence"
				description: "Verifies that ResourceQuota and LimitRange objects exist in all critical application namespaces."
				constraints: {
					check_id: "resource_quotas_exist"
					pass:     true
				}
			}]
		},
	}
}
