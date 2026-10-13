package compliance_framework.restrict_admin_ingress

test_risk_template_violation_id if {
	risk_templates[0].violation_ids == ["nacl_unapproved_admin_ingress"]
}

test_violation_ssh_from_public_source if {
	count(violation) == 1 with input as {"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "Protocol": "6", "PortRange": {"From": 22, "To": 22}, "CidrBlock": "0.0.0.0/0"}]}}
}

test_violation_all_protocol_from_public_source if {
	count(violation) == 1 with input as {"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "Protocol": "-1", "CidrBlock": "0.0.0.0/0"}]}}
}

test_no_violation_ssh_from_approved_source if {
	count(violation) == 0 with input as {"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "Protocol": "6", "PortRange": {"From": 22, "To": 22}, "CidrBlock": "203.0.113.0/24"}]}}
		with data.approved_admin_cidrs as ["203.0.113.0/24"] # regal ignore:unresolved-reference
}

test_no_violation_non_admin_port_from_public_source if {
	count(violation) == 0 with input as {"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "Protocol": "6", "PortRange": {"From": 443, "To": 443}, "CidrBlock": "0.0.0.0/0"}]}}
}

test_no_violation_egress_admin_port if {
	count(violation) == 0 with input as {"network_acl": {"Entries": [{"Egress": true, "RuleAction": "allow", "Protocol": "6", "PortRange": {"From": 22, "To": 22}, "CidrBlock": "0.0.0.0/0"}]}}
}

test_no_violation_custom_admin_port_not_configured if {
	count(violation) == 0 with input as {"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "Protocol": "6", "PortRange": {"From": 8443, "To": 8443}, "CidrBlock": "0.0.0.0/0"}]}}
}

test_violation_custom_admin_port_configured if {
	count(violation) == 1 with input as {"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "Protocol": "6", "PortRange": {"From": 8443, "To": 8443}, "CidrBlock": "0.0.0.0/0"}]}}
		with data.approved_admin_ports as [8443] # regal ignore:unresolved-reference
}
