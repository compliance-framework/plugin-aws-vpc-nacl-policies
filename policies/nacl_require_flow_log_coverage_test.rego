package compliance_framework.require_flow_log_coverage

test_risk_template_violation_id if {
	risk_templates[0].violation_ids == ["nacl_flow_log_coverage_not_compliant"]
}

test_no_violation_vpc_flow_log_covers_associated_subnets if {
	count(violation) == 0 with input as {
		"network_acl": {"Associations": [{"SubnetId": "subnet-1"}, {"SubnetId": "subnet-2"}]},
		"nacl_context": {
			"current": {"associated_subnet_ids": ["subnet-1", "subnet-2"]},
			"flow_logs_for_vpc": [{"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE", "TrafficType": "ALL"}],
			"flow_logs_for_associated_subnets": [],
		},
	}
}

test_no_violation_each_associated_subnet_has_flow_log if {
	count(violation) == 0 with input as {
		"network_acl": {"Associations": [{"SubnetId": "subnet-1"}, {"SubnetId": "subnet-2"}]},
		"nacl_context": {
			"current": {"associated_subnet_ids": ["subnet-1", "subnet-2"]},
			"flow_logs_for_vpc": [],
			"flow_logs_for_associated_subnets": [
				{"ResourceId": "subnet-1", "FlowLogStatus": "ACTIVE", "TrafficType": "ALL"},
				{"ResourceId": "subnet-2", "FlowLogStatus": "ACTIVE", "TrafficType": "ALL"},
			],
		},
	}
}

test_violation_no_flow_log_coverage if {
	count(violation) == 1 with input as {
		"network_acl": {"Associations": [{"SubnetId": "subnet-1"}]},
		"nacl_context": {
			"current": {"associated_subnet_ids": ["subnet-1"]},
			"flow_logs_for_vpc": [],
			"flow_logs_for_associated_subnets": [],
		},
	}
}

test_violation_inactive_flow_log if {
	count(violation) == 1 with input as {
		"network_acl": {"Associations": [{"SubnetId": "subnet-1"}]},
		"nacl_context": {
			"current": {"associated_subnet_ids": ["subnet-1"]},
			"flow_logs_for_vpc": [{"ResourceId": "vpc-1", "FlowLogStatus": "FAILED", "TrafficType": "ALL"}],
			"flow_logs_for_associated_subnets": [],
		},
	}
}

test_violation_accept_only_flow_log if {
	count(violation) == 1 with input as {
		"network_acl": {"Associations": [{"SubnetId": "subnet-1"}]},
		"nacl_context": {
			"current": {"associated_subnet_ids": ["subnet-1"]},
			"flow_logs_for_vpc": [{"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE", "TrafficType": "ACCEPT"}],
			"flow_logs_for_associated_subnets": [],
		},
	}
}

test_no_violation_custom_required_traffic_type if {
	count(violation) == 0 with input as {
		"network_acl": {"Associations": [{"SubnetId": "subnet-1"}]},
		"nacl_context": {
			"current": {"associated_subnet_ids": ["subnet-1"]},
			"flow_logs_for_vpc": [{"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE", "TrafficType": "REJECT"}],
			"flow_logs_for_associated_subnets": [],
		},
	}
		with data.required_nacl_flow_log_traffic_types as ["REJECT"] # regal ignore:unresolved-reference
}

test_skip_unassociated_nacl if {
	skip_reason == "Network ACL has no subnet associations" with input as {
		"network_acl": {"Associations": []},
		"nacl_context": {"current": {"associated_subnet_ids": []}, "flow_logs_for_vpc": [], "flow_logs_for_associated_subnets": []},
	}
}
