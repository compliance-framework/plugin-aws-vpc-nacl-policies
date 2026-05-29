package compliance_framework.require_flow_log_coverage

risk_templates := [{
  "name": "Network ACL related flow log coverage is not compliant",
  "title": "Network ACL traffic logging gap",
  "statement": "Associated subnets or the parent VPC do not have approved flow log coverage, reducing the ability to detect, investigate, and audit network activity affecting traffic governed by the Network ACL.",
  "likelihood_hint": "medium",
  "impact_hint": "medium",
  "violation_ids": ["nacl_flow_log_coverage_not_compliant"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-778",
      "title": "Insufficient Logging",
      "url": "https://cwe.mitre.org/data/definitions/778.html"
    }
  ],
  "remediation": {
    "title": "Enable approved flow log coverage for Network ACL traffic",
    "description": "Ensure the parent VPC or every subnet associated with the Network ACL has flow logs in approved statuses and with the required traffic capture.",
    "tasks": [
      {"title": "Identify whether flow log coverage should be satisfied at the VPC level or per associated subnet"},
      {"title": "Enable flow logs for uncovered associated subnets or the parent VPC"},
      {"title": "Use approved flow log statuses and required traffic types"},
      {"title": "Confirm log delivery reaches the expected destination for monitoring and retention"}
    ]
  }
}]

approved_flow_log_status(status) if {
	approved := data.approved_nacl_flow_log_statuses[_]
	upper(status) == upper(approved)
}

required_flow_log_traffic_type(traffic_type) if {
	required := data.required_nacl_flow_log_traffic_types[_]
	upper(traffic_type) == upper(required)
}

flow_log_approved(flow_log) if {
	approved_flow_log_status(object.get(flow_log, "FlowLogStatus", ""))
	required_flow_log_traffic_type(object.get(flow_log, "TrafficType", ""))
}

associated_subnet_id[id] if {
	id := input.nacl_context.current.associated_subnet_ids[_]
}

associated_subnet_id[id] if {
	association := input.network_acl.Associations[_]
	id := object.get(association, "SubnetId", "")
	id != ""
}

vpc_flow_log_coverage if {
	flow_log := input.nacl_context.flow_logs_for_vpc[_]
	flow_log_approved(flow_log)
}

subnet_flow_log_coverage(subnet_id) if {
	flow_log := input.nacl_context.flow_logs_for_associated_subnets[_]
	object.get(flow_log, "ResourceId", "") == subnet_id
	flow_log_approved(flow_log)
}

missing_flow_log_coverage[subnet_id] if {
	associated_subnet_id[subnet_id]
	not vpc_flow_log_coverage
	not subnet_flow_log_coverage(subnet_id)
}

violation[{"id": "nacl_flow_log_coverage_not_compliant"}] if {
	count(missing_flow_log_coverage) > 0
}

skip_reason := "Network ACL has no subnet associations" if {
	count(associated_subnet_id) == 0
}

title := "Network ACL associated subnets should have flow log coverage"
description := sprintf("Network ACL associated subnets should be covered by VPC or subnet flow logs with approved statuses: %s and traffic types: %s", [concat(", ", data.approved_nacl_flow_log_statuses), concat(", ", data.required_nacl_flow_log_traffic_types)])
