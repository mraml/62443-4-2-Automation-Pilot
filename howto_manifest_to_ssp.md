Step-by-step process to connect your manifests to your SSP

1. Store Manifests in a Git Repository
Ensure that all your Kubernetes manifests, like the ones in your openshift_iac_for_62443.yaml file, are stored and managed in a version-controlled Git repository. This is your auditable, authoritative source for the system's configuration.

2. Reference the Git Repository in the SSP
In your OSCAL SSP file, you'll add a resource in the back-matter that points to your Git repository. This creates a formal link between your compliance document and your code.
Example SSP Snippet:
```
JSON
"back-matter": {
  "resources": [
    {
      "uuid": "a1b2c3d4-repo-link",
      "title": "OpenShift GitOps Configuration Repository",
      "description": "The single source of truth for all Kubernetes manifests defining the security configuration of the production OpenShift cluster.",
      "rlinks": [
        {
          "href": "https://github.com/example-corp/ics-openshift-config",
          "media-type": "application/vnd.github.v3+json"
        }
      ]
    }
  ]
}
```

4. Write the Implementation Narrative in the SSP
For each control in your SSP's control-implementation section, you write a clear, human-readable narrative that explains how the manifests in your repository implement that control. You then link this statement to the component that does the work.
Example SSP Snippet for CR-5.1:
```
JSON
"control-implementation": {
  "description": "This section describes how controls are implemented.",
  "implemented-requirements": [
    {
      "control-id": "cr-5.1",
      "description": "This control is implemented by the 'default-deny-ingress' NetworkPolicy manifest, which is stored and managed in our GitOps repository (see linked resource). This policy is applied to all critical application namespaces and blocks all ingress traffic by default, enforcing a principle of least privilege for network communication.",
      "by-components": [
        {
          "component-uuid": "e9f8a7b6-c5d4-4e3f-a92f-5d5d5d5d5d5d"
        }
      ]
    }
  ]
}
```

This approach creates a clear, auditable trail. An auditor can read the SSP, understand the implementation, and follow the link to the Git repository to see the exact code that enforces the control.

