package main

// Gamera Mapping for Red Hat Device Edge (RHDE) + MicroShift aligned with ISA/IEC 62443-4-2 SL-4.
// This file defines the comprehensive, line-by-line evidence required to satisfy
// each security control for a production-ready, evidence-based assessment.
// It requires two primary evidence types: one for the immutable image build (rhde_image_build_report)
// and one for the live runtime (microshift_runtime_evidence).
mapping: {
	controls: {
		// --- FR 1: Identification & Authentication Control ---
		"cr-1.1_re.2": { // Human User MFA
			evidence: [{
				type:        "external_evidence"
				description: "Requires evidence from the central IdP (e.g., a configuration export) showing that MFA is enforced for the edge device user group."
				constraints: { check_id: "idp_edge_mfa_policy", pass: true }
			}]
		},
		"cr-1.5_re.1": { // Hardware Security for Authenticators
			evidence: [{
				type:        "rhde_image_build_report"
				description: "Verifies the RHEL for Edge image was built with LUKS disk encryption enabled and configured to bind to the hardware TPM."
				constraints: { check_id: "cr-1.5_re.1", changed: false }
			}]
		},
		"cr-1.12": { // System Use Notification
			evidence: [{
				type:        "rhde_image_build_report"
				description: "Verifies that /etc/motd was baked into the RHEL for Edge image with the approved system use banner."
				constraints: { check_id: "cr-1.12", changed: false }
			}]
		},

		// --- FR 2: Use Control ---
		"cr-2.1_re.2": { // Authorization Enforcement
			evidence: [{
				type:        "rhde_image_build_report"
				description: "Verifies the RHEL for Edge image was built with SELinux in enforcing mode."
				constraints: { check_id: "selinux_enforcing", changed: false }
			}, {
				type:        "microshift_runtime_evidence"
				description: "Verifies that MicroShift RBAC rules are in place to restrict administrative privileges."
				constraints: { check_id: "microshift_rbac_configured", pass: true }
			}]
		},
		"cr-2.8": { // Auditable Events
			evidence: [{
				type:        "rhde_image_build_report"
				description: "Verifies the RHEL for Edge image was built with the auditd service enabled and a comprehensive rule set."
				constraints: { check_id: "cr-2.8", changed: false }
			}]
		},
		"cr-2.11_re.2": { // Time Synchronization & Integrity
			evidence: [{
				type:        "rhde_image_build_report"
				description: "Verifies the RHEL for Edge image was built with chronyd configured to use trusted NTP sources."
				constraints: { check_id: "cr-2.11_re.2", changed: false }
			}]
		},
		"sar-2.4_re.1": { // Mobile Code & Authenticity Check (for containers)
			description: "This control is satisfied by software supply chain evidence for every application container image deployed via the GitOps pipeline."
			evidence: [
				{ type: "sbom", description: "A CycloneDX SBOM must be present for the container image." },
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
				type:        "rhde_image_build_report"
				description: "Verifies the RHEL for Edge image was built with the system-wide crypto policy set to 'FIPS'."
				constraints: { check_id: "cr-3.1_re.1", changed: false }
			}]
		},
		"cr-3.4_re.2": { // Software/Info Integrity & Notification
			evidence: [{
				type:        "rhde_image_build_report"
				description: "Verifies the RHEL for Edge image was built with AIDE and a cron job to report integrity violations."
				constraints: { check_id: "cr-3.4_re.2", changed: false }
			}]
		},
		"hdr-3.10_re.1": { // Update Authenticity and Integrity
			evidence: [{
				type:        "rhde_image_build_report"
				description: "Verifies the RHEL for Edge image was built with rpm-ostree configured to perform GPG signature checks on all updates."
				constraints: { check_id: "hdr-3.10_re.1", changed: false }
			}]
		},

		// --- FR 4: Data Confidentiality ---
		"cr-4.1": { // Information Confidentiality
			evidence: [{
				type:        "rhde_image_build_report"
				description: "Verifies the RHEL for Edge image was built to use LUKS encryption for all persistent data volumes."
				constraints: { check_id: "cr-4.1", changed: false }
			}]
		},
		"cr-4.3": { // Use of Cryptography
			evidence: [{
				type:        "rhde_image_build_report"
				description: "Verifies the RHEL for Edge image was built with FIPS mode enabled."
				constraints: { check_id: "cr-4.3", changed: false }
			}]
		},

		// --- FR 5: Restricted Data Flow ---
		"cr-5.1": {
			evidence: [{
				type:        "microshift_runtime_evidence"
				description: "Verifies that a 'default-deny-ingress' NetworkPolicy exists in all application namespaces in the MicroShift runtime."
				constraints: { check_id: "default_deny_network_policy_exists", pass: true }
			}]
		},

		// --- FR 6: Timely Response to Events ---
		"cr-6.2": { // Continuous Monitoring
			evidence: [{
				type:        "rhde_image_build_report"
				description: "Verifies the RHEL for Edge image was built with log forwarding configured to send all system logs to a central SIEM."
				constraints: { check_id: "cr-6.2", changed: false }
			}]
		},

		// --- FR 7: Resource Availability ---
		"cr-7.2": {
			evidence: [{
				type:        "microshift_runtime_evidence"
				description: "Verifies that ResourceQuota and LimitRange objects are applied to all application namespaces to prevent resource exhaustion."
				constraints: { check_id: "resource_quotas_exist", pass: true }
			}]
		},
		"cr-7.7": {
			evidence: [{
				type:        "rhde_image_build_report"
				description: "Verifies the RHEL for Edge image was built with a minimal package set, ensuring least functionality."
				constraints: { check_id: "cr-7.7", changed: false }
			}]
		},
	}
}
