package compliance_framework.deny_unrestricted_public_egress

test_risk_template_violation_id if {
	risk_templates[0].violation_ids == ["nacl_unrestricted_public_egress"]
}

test_no_violation_private_egress_cidr if {
	count(violation) == 0 with input as {"network_acl": {"Entries": [{"Egress": true, "RuleAction": "allow", "CidrBlock": "10.0.1.0/24"}]}}
}

test_violation_public_all_protocol_egress if {
	count(violation) == 1 with input as {"network_acl": {"Entries": [{"Egress": true, "RuleAction": "allow", "Protocol": "-1", "CidrBlock": "0.0.0.0/0"}]}}
}

test_violation_public_all_ports_egress if {
	count(violation) == 1 with input as {"network_acl": {"Entries": [{"Egress": true, "RuleAction": "allow", "Protocol": "6", "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 0, "To": 65535}}]}}
}

test_no_violation_denied_public_all_protocol_egress if {
	count(violation) == 0 with input as {"network_acl": {"Entries": [{"Egress": true, "RuleAction": "deny", "Protocol": "-1", "CidrBlock": "0.0.0.0/0"}]}}
}

test_no_violation_public_constrained_port_egress if {
	count(violation) == 0 with input as {"network_acl": {"Entries": [{"Egress": true, "RuleAction": "allow", "Protocol": "6", "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 443, "To": 443}}]}}
}

test_no_violation_public_ingress_rule if {
	count(violation) == 0 with input as {"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "Protocol": "-1", "CidrBlock": "0.0.0.0/0"}]}}
}

test_violation_public_ipv6_all_protocol_egress if {
	count(violation) == 1 with input as {"network_acl": {"Entries": [{"Egress": true, "RuleAction": "allow", "Protocol": "-1", "Ipv6CidrBlock": "::/0"}]}}
}

test_no_violation_public_ipv6_constrained_port_egress if {
	count(violation) == 0 with input as {"network_acl": {"Entries": [{"Egress": true, "RuleAction": "allow", "Protocol": "6", "Ipv6CidrBlock": "::/0", "PortRange": {"From": 443, "To": 443}}]}}
}
