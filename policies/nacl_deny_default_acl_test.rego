package compliance_framework.deny_default_acl

test_risk_template_violation_id if {
	risk_templates[0].violation_ids == ["nacl_default_acl_in_use"]
}

test_violation_default_nacl_from_network_acl_field if {
	count(violation) == 1 with input as {
		"network_acl": {"IsDefault": true},
		"nacl_context": {"current": {"is_default": false}}
	}
}

test_violation_default_nacl_from_context_field if {
	count(violation) == 1 with input as {
		"network_acl": {"IsDefault": false},
		"nacl_context": {"current": {"is_default": true}}
	}
}

test_no_violation_default_nacl_allowed if {
	count(violation) == 0 with input as {
		"network_acl": {"IsDefault": true},
		"nacl_context": {"current": {"is_default": true}}
	} with data.allow_default_nacl as true
}

test_skip_non_default_nacl if {
	skip_reason == "Network ACL is not the default Network ACL" with input as {
		"network_acl": {"IsDefault": false},
		"nacl_context": {"current": {"is_default": false}}
	}
}

test_title_defined_for_default_nacl if {
	title == "Default Network ACLs should not be used" with input as {
		"network_acl": {"IsDefault": true}
	}
}

test_title_undefined_for_non_default_nacl if {
	not title with input as {
		"network_acl": {"IsDefault": false},
		"nacl_context": {"current": {"is_default": false}}
	}
}
