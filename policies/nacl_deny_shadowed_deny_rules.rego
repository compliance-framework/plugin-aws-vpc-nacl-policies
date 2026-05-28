package compliance_framework.deny_shadowed_deny_rules

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

same_direction(first, second) if {
	object.get(first, "Egress", false) == object.get(second, "Egress", false)
}

protocol_covers(allow_entry, deny_entry) if {
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

port_covers(allow_entry, deny_entry) if {
	entry_protocol(allow_entry) == "-1"
}

port_covers(allow_entry, deny_entry) if {
	entry_from_port(allow_entry) <= entry_from_port(deny_entry)
	entry_to_port(allow_entry) >= entry_to_port(deny_entry)
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
	port_covers(allow_entry, deny_entry)
}

violation[{}] if {
	count(shadowed_deny_rule) > 0
}

title := "Network ACL deny rules should not be shadowed by earlier allow rules"
description := "Network ACL rules are evaluated by ascending rule number, so deny rules should not appear after broader allow rules that already match the same direction, protocol, CIDR, and port range"
