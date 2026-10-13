package compliance_framework.deny_shadowed_deny_rules

risk_templates := [{
	"name": "Network ACL deny rules are shadowed by earlier allow rules",
	"title": "Ineffective Network ACL deny protection",
	"statement": "A broader allow rule appears before a deny rule and already matches the same direction, protocol, CIDR, and traffic selector, making the deny ineffective and weakening the intended network access control boundary.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["nacl_shadowed_deny_rule"],
	"threat_refs": [
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-693",
			"title": "Protection Mechanism Failure",
			"url": "https://cwe.mitre.org/data/definitions/693.html",
		},
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-284",
			"title": "Improper Access Control",
			"url": "https://cwe.mitre.org/data/definitions/284.html",
		},
	],
	"remediation": {
		"title": "Reorder or narrow Network ACL rules so deny logic remains effective",
		"description": "Update rule order or scope so earlier allow rules do not fully cover later deny rules that are intended to enforce network restrictions.",
		"tasks": [
			{"title": "Identify deny rules that are fully covered by earlier allow rules"},
			{"title": "Move deny rules ahead of broader allow rules where appropriate"},
			{"title": "Narrow overly broad allow rules so they no longer bypass the intended deny behavior"},
			{"title": "Validate the resulting rule order against expected ingress and egress traffic paths"},
		],
	},
}]

entry_protocol(entry) := protocol if {
	protocol := lower(sprintf("%v", [object.get(entry, "Protocol", "-1")]))
}

entry_rule_action(entry) := action if {
	action := lower(sprintf("%v", [object.get(entry, "RuleAction", "")]))
}

entry_from_port(entry) := from_port if {
	port_range := object.get(entry, "PortRange", {})
	from_port := object.get(port_range, "From", 0)
}

entry_to_port(entry) := to_port if {
	port_range := object.get(entry, "PortRange", {})
	to_port := object.get(port_range, "To", 65535)
}

entry_icmp_type(entry) := icmp_type if {
	icmp_type_code := object.get(entry, "IcmpTypeCode", {})
	icmp_type := object.get(icmp_type_code, "Type", -1)
}

entry_icmp_code(entry) := icmp_code if {
	icmp_type_code := object.get(entry, "IcmpTypeCode", {})
	icmp_code := object.get(icmp_type_code, "Code", -1)
}

same_direction(first, second) if {
	object.get(first, "Egress", false) == object.get(second, "Egress", false)
}

protocol_covers(allow_entry, _) if {
	entry_protocol(allow_entry) == "-1"
}

protocol_covers(allow_entry, deny_entry) if {
	entry_protocol(allow_entry) == entry_protocol(deny_entry)
}

cidr_covers(allow_entry, deny_entry) if {
	allow_cidr := object.get(allow_entry, "CidrBlock", "")
	deny_cidr := object.get(deny_entry, "CidrBlock", "")
	allow_cidr != ""
	deny_cidr != ""
	net.cidr_contains(allow_cidr, deny_cidr)
}

cidr_covers(allow_entry, deny_entry) if {
	allow_cidr := object.get(allow_entry, "Ipv6CidrBlock", "")
	deny_cidr := object.get(deny_entry, "Ipv6CidrBlock", "")
	allow_cidr != ""
	deny_cidr != ""
	net.cidr_contains(allow_cidr, deny_cidr)
}

port_range_protocol(entry) if {
	protocol := entry_protocol(entry)
	protocol in ["6", "tcp", "17", "udp"]
}

icmp_protocol(entry) if {
	protocol := entry_protocol(entry)
	protocol in ["1", "icmp", "58", "icmpv6"]
}

port_covers(allow_entry, deny_entry) if {
	entry_from_port(allow_entry) <= entry_from_port(deny_entry)
	entry_to_port(allow_entry) >= entry_to_port(deny_entry)
}

icmp_type_covers(allow_entry, _) if {
	entry_icmp_type(allow_entry) == -1
}

icmp_type_covers(allow_entry, deny_entry) if {
	entry_icmp_type(allow_entry) == entry_icmp_type(deny_entry)
}

icmp_code_covers(allow_entry, _) if {
	entry_icmp_type(allow_entry) == -1
}

icmp_code_covers(allow_entry, _) if {
	entry_icmp_code(allow_entry) == -1
}

icmp_code_covers(allow_entry, deny_entry) if {
	entry_icmp_code(allow_entry) == entry_icmp_code(deny_entry)
}

icmp_type_code_covers(allow_entry, deny_entry) if {
	icmp_type_covers(allow_entry, deny_entry)
	icmp_code_covers(allow_entry, deny_entry)
}

traffic_selector_covers(allow_entry, _) if {
	entry_protocol(allow_entry) == "-1"
}

traffic_selector_covers(allow_entry, deny_entry) if {
	port_range_protocol(allow_entry)
	port_covers(allow_entry, deny_entry)
}

traffic_selector_covers(allow_entry, deny_entry) if {
	icmp_protocol(allow_entry)
	icmp_type_code_covers(allow_entry, deny_entry)
}

traffic_selector_covers(allow_entry, _) if {
	not port_range_protocol(allow_entry)
	not icmp_protocol(allow_entry)
}

shadowed_deny_rule[deny_entry] if {
	allow_entry := input.network_acl.Entries[_]
	deny_entry := input.network_acl.Entries[_]
	entry_rule_action(allow_entry) == "allow"
	entry_rule_action(deny_entry) == "deny"
	object.get(allow_entry, "RuleNumber", 32767) < object.get(deny_entry, "RuleNumber", 32767)
	same_direction(allow_entry, deny_entry)
	protocol_covers(allow_entry, deny_entry)
	cidr_covers(allow_entry, deny_entry)
	traffic_selector_covers(allow_entry, deny_entry)
}

violation[{"id": "nacl_shadowed_deny_rule"}] if {
	count(shadowed_deny_rule) > 0
}

title := "Network ACL deny rules should not be shadowed by earlier allow rules"
description := "Network ACL rules are evaluated by ascending rule number, so deny rules should not appear after broader allow rules that already match the same direction, protocol, CIDR, and traffic selector"
