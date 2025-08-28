OSCAL-based GRC Automation for ISA/IEC 62443-4-2

This repository contains a complete set of artifacts for piloting a comprehensive, automated Governance, Risk, and Compliance (GRC) lifecycle for industrial control systems based on the ISA/IEC 62443-4-2 standard. It uses the Open Security Controls Assessment Language (OSCAL) to create a machine-readable, auditable, and automated compliance process.
Repository Structure

This repository is organized to follow the OSCAL GRC lifecycle, from defining requirements to automating implementation and assessment.

.
├── catalog/
│   └── 62443-4-2_catalog.json        # OSCAL Control Catalog for the standard
│
├── components/
│   ├── ocp4_component-definition.json    # OSCAL Component Definition for OpenShift 4
│   ├── rhel9_component-definition.json   # OSCAL Component Definition for RHEL 9
│   ├── aap_component-definition.json     # OSCAL Component Definition for AAP 2.5+
│   └── rhde_component-definition.json    # OSCAL Component Definition for Red Hat Device Edge
│
├── implementation/
│   ├── ocp4_implementation.yaml          # Automation code (manifests) for OpenShift 4
│   ├── rhel9_implementation.yaml         # Automation code (playbook) for RHEL 9
│   ├── aap_implementation.yaml           # Automation code (playbook) for AAP host
│   └── rhde_implementation.yaml          # Automation profile for Red Hat Device Edge
│
├── assessment/
│   ├── ocp4_assessment-plan.json         # OSCAL Assessment Plan for OpenShift 4
│   ├── rhel9_assessment-plan.json        # OSCAL Assessment Plan for RHEL 9
│   ├── aap_assessment-plan.json          # OSCAL Assessment Plan for AAP 2.5+
│   └── rhde_assessment-plan.json         # OSCAL Assessment Plan for Red Hat Device Edge
│
├── procedures/
│   ├── ocp4_manual_guide.md              # Guide for manual controls in OpenShift 4
│   ├── rhel9_manual_guide.md             # Guide for manual controls in RHEL 9
│   ├── aap_manual_guide.md               # Guide for manual controls in AAP 2.5+
│   └── rhde_manual_guide.md              # Guide for manual controls in Red Hat Device Edge
│
└── README.md                             # This file

The OSCAL GRC Lifecycle

This repository enables a complete, end-to-end compliance lifecycle:

    Catalog (catalog/): We start with a machine-readable version of the ISA/IEC 62443-4-2 standard. This is the "source of truth" for all security requirements.

    Component Definition (components/): We define how a specific technology (like OpenShift or RHEL 9) can meet the controls from the catalog. This is a reusable "statement of capabilities."

    Implementation as Code (implementation/): We use automation code (Ansible playbooks and Kubernetes manifests) to technically enforce the security controls on live systems.

    System Security Plan (SSP) (User-Created): You create an SSP for your specific system (e.g., "Manufacturing Line 3"). This document imports our component definitions and describes your unique deployment.

    Assessment Plan (assessment/): We provide a detailed plan that outlines the exact steps to test and verify that each control is implemented correctly in a live system.

    Assessment Results (User-Created): You execute the assessment plan against your system and record the findings in an OSCAL Assessment Results file. This, along with your SSP, is the primary evidence you provide to an auditor.

How to Use This Repository to Pilot Your GRC Automation

    Review the Artifacts: Familiarize yourself with the control catalog, the component definition for your target technology, and the corresponding assessment plan.

    Create a System Security Plan (SSP): Create a new OSCAL SSP file. In this file, you will import the component definition for your technology (e.g., ocp4_component-definition.json). You will then provide the system-specific details (e.g., hostnames, IP addresses, user groups) that make the implementation unique to your environment.

    Apply the Automation: Use the automation code from the implementation/ directory to configure and harden a pilot system.

        For RHEL 9 / AAP, run the Ansible playbook against your target hosts.

        For OpenShift / RHDE, apply the Kubernetes manifests to your cluster, preferably via a GitOps workflow.

    Execute the Assessment: Follow the steps in the corresponding Assessment Plan from the assessment/ directory. For each control, perform the Examine, Interview, and Test procedures against your pilot system.

    Generate the Results: Record your findings in a new OSCAL Assessment Results file. For any controls that fail the assessment, create a Plan of Action and Milestones (POA&M) to track their remediation.

    Present to Auditors: You now have a complete, machine-readable, and human-readable compliance package (SSP, Assessment Plan, Assessment Results, POA&M) that provides a clear and auditable trail from the standard's requirements to your live implementation.

Components Covered

This repository provides GRC automation content for the following Red Hat products, targeting an ISA/IEC 62443-4-2 Security Level 4 (SL-4) baseline:

    Red Hat OpenShift Container Platform 4

    Red Hat Enterprise Linux 9

    Ansible Automation Platform 2.5+

    Red Hat Device Edge (MicroShift on RHEL for Edge)
