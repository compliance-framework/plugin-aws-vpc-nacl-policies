package compliance_framework.deny_default_acl

risk_templates := [{
  "name": "Default Network ACL is in use",
  "title": "Default Network ACL usage",
  "statement": "A default Network ACL is associated with network traffic controls. Default Network ACLs can retain broad baseline rules and make it harder to demonstrate intentional subnet-level traffic filtering.",
  "likelihood_hint": "medium",
  "impact_hint": "medium",
  "violation_ids": ["nacl_default_acl_in_use"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-693",
      "title": "Protection Mechanism Failure",
      "url": "https://cwe.mitre.org/data/definitions/693.html"
    }
  ],
  "remediation": {
    "title": "Replace default Network ACL usage with managed Network ACLs",
    "description": "Use explicitly managed Network ACLs for subnet associations unless default Network ACL usage is intentionally allowed by policy data.",
    "tasks": [
      {"title": "Identify subnet associations that still use the default Network ACL"},
      {"title": "Create or select a managed Network ACL with intentional ingress and egress rules"},
      {"title": "Associate affected subnets with the managed Network ACL"},
      {"title": "Confirm the default Network ACL is not relied on for production traffic filtering"}
    ]
  }
}]

network_acl_default if {
	object.get(object.get(input, "network_acl", {}), "IsDefault", false)
}

context_default if {
	nacl_context := object.get(input, "nacl_context", {})
	current := object.get(nacl_context, "current", {})
	object.get(current, "is_default", false)
}

default_nacl if {
	network_acl_default
}

default_nacl if {
	context_default
}

violation[{"id": "nacl_default_acl_in_use"}] if {
	not data.allow_default_nacl
	default_nacl
}

skip_reason := "Network ACL is not the default Network ACL" if {
	not default_nacl
}

title := "Default Network ACLs should not be used" if {
	default_nacl
}

description := "Network ACL should not be the default Network ACL unless default Network ACL usage is explicitly allowed by policy data" if {
	default_nacl
}
