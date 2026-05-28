package compliance_framework.deny_unapproved_ingress_cidrs

test_no_violation_private_ingress_cidr if {
	count(violation) == 0 with input as {
		"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "CidrBlock": "10.0.1.0/24", "PortRange": {"From": 22, "To": 22}}]}
	}
}

test_no_violation_public_https_ingress if {
	count(violation) == 0 with input as {
		"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "CidrBlock": "0.0.0.0/0", "Protocol": "6", "PortRange": {"From": 443, "To": 443}}]}
	}
}

test_violation_public_ssh_ingress if {
	count(violation) == 1 with input as {
		"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "CidrBlock": "0.0.0.0/0", "Protocol": "6", "PortRange": {"From": 22, "To": 22}}]}
	}
}

test_violation_public_all_ports_ingress if {
	count(violation) == 1 with input as {
		"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "CidrBlock": "0.0.0.0/0", "Protocol": "6", "PortRange": {"From": 0, "To": 65535}}]}
	}
}

test_violation_public_all_protocol_ingress if {
	count(violation) == 1 with input as {
		"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "CidrBlock": "0.0.0.0/0", "Protocol": "-1"}]}
	}
}

test_no_violation_denied_public_ingress if {
	count(violation) == 0 with input as {
		"network_acl": {"Entries": [{"Egress": false, "RuleAction": "deny", "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 22, "To": 22}}]}
	}
}

test_no_violation_custom_public_ingress_port if {
	count(violation) == 0 with input as {
		"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "CidrBlock": "0.0.0.0/0", "Protocol": "6", "PortRange": {"From": 8443, "To": 8443}}]}
	} with data.approved_nacl_public_ingress_ports as [8443]
}

test_violation_public_ipv6_ssh_ingress if {
	count(violation) == 1 with input as {
		"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "Ipv6CidrBlock": "::/0", "Protocol": "6", "PortRange": {"From": 22, "To": 22}}]}
	}
}

test_no_violation_public_ipv6_https_ingress if {
	count(violation) == 0 with input as {
		"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "Ipv6CidrBlock": "::/0", "Protocol": "6", "PortRange": {"From": 443, "To": 443}}]}
	}
}


test_violation_public_ipv6_all_protocol_ingress if {
	count(violation) == 1 with input as {
		"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "Ipv6CidrBlock": "::/0", "Protocol": "-1"}]}
	}
}

test_violation_public_ipv6_all_ports_ingress if {
	count(violation) == 1 with input as {
		"network_acl": {"Entries": [{"Egress": false, "RuleAction": "allow", "Ipv6CidrBlock": "::/0", "Protocol": "6", "PortRange": {"From": 0, "To": 65535}}]}
	}
}
