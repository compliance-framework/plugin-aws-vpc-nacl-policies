package compliance_framework.require_subnet_association

test_no_violation_associated_nacl if {
	count(violation) == 0 with input as {
		"network_acl": {"Associations": [{"SubnetId": "subnet-123"}]}
	}
}

test_violation_unassociated_nacl if {
	count(violation) == 1 with input as {
		"network_acl": {"Associations": []}
	}
}

test_no_violation_unassociated_nacl_allowed if {
	count(violation) == 0 with input as {
		"network_acl": {"Associations": []}
	} with data.allow_unassociated_nacl as true
}
