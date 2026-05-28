package compliance_framework.deny_shadowed_deny_rules

test_violation_ingress_deny_shadowed_by_public_allow if {
	count(violation) == 1 with input as {
		"network_acl": {"Entries": [
			{"RuleNumber": 100, "RuleAction": "allow", "Egress": false, "Protocol": "6", "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 0, "To": 65535}},
			{"RuleNumber": 110, "RuleAction": "deny", "Egress": false, "Protocol": "6", "CidrBlock": "203.0.113.0/24", "PortRange": {"From": 22, "To": 22}}
		]}
	}
}

test_violation_egress_deny_shadowed_by_all_protocol_allow if {
	count(violation) == 1 with input as {
		"network_acl": {"Entries": [
			{"RuleNumber": 100, "RuleAction": "allow", "Egress": true, "Protocol": "-1", "CidrBlock": "0.0.0.0/0"},
			{"RuleNumber": 120, "RuleAction": "deny", "Egress": true, "Protocol": "6", "CidrBlock": "198.51.100.0/24", "PortRange": {"From": 443, "To": 443}}
		]}
	}
}

test_violation_ipv6_deny_shadowed_by_public_allow if {
	count(violation) == 1 with input as {
		"network_acl": {"Entries": [
			{"RuleNumber": 100, "RuleAction": "allow", "Egress": false, "Protocol": "6", "Ipv6CidrBlock": "::/0", "PortRange": {"From": 0, "To": 65535}},
			{"RuleNumber": 110, "RuleAction": "deny", "Egress": false, "Protocol": "6", "Ipv6CidrBlock": "2001:db8:1::/64", "PortRange": {"From": 22, "To": 22}}
		]}
	}
}

test_no_violation_deny_before_allow if {
	count(violation) == 0 with input as {
		"network_acl": {"Entries": [
			{"RuleNumber": 90, "RuleAction": "deny", "Egress": false, "Protocol": "6", "CidrBlock": "203.0.113.0/24", "PortRange": {"From": 22, "To": 22}},
			{"RuleNumber": 100, "RuleAction": "allow", "Egress": false, "Protocol": "6", "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 0, "To": 65535}}
		]}
	}
}

test_no_violation_different_direction if {
	count(violation) == 0 with input as {
		"network_acl": {"Entries": [
			{"RuleNumber": 100, "RuleAction": "allow", "Egress": true, "Protocol": "6", "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 0, "To": 65535}},
			{"RuleNumber": 110, "RuleAction": "deny", "Egress": false, "Protocol": "6", "CidrBlock": "203.0.113.0/24", "PortRange": {"From": 22, "To": 22}}
		]}
	}
}

test_no_violation_earlier_allow_does_not_cover_deny_port if {
	count(violation) == 0 with input as {
		"network_acl": {"Entries": [
			{"RuleNumber": 100, "RuleAction": "allow", "Egress": false, "Protocol": "6", "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 443, "To": 443}},
			{"RuleNumber": 110, "RuleAction": "deny", "Egress": false, "Protocol": "6", "CidrBlock": "203.0.113.0/24", "PortRange": {"From": 22, "To": 22}}
		]}
	}
}
