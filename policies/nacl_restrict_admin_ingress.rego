package compliance_framework.restrict_admin_ingress

admin_protocol(entry) if {
	object.get(entry, "Protocol", "-1") == "-1"
}

admin_protocol(entry) if {
	object.get(entry, "Protocol", "") == "6"
}

admin_protocol(entry) if {
	lower(object.get(entry, "Protocol", "")) == "tcp"
}

entry_matches_admin_port(entry) if {
	admin_protocol(entry)
	object.get(entry, "Protocol", "-1") == "-1"
}

entry_matches_admin_port(entry) if {
	admin_protocol(entry)
	port_range := object.get(entry, "PortRange", {})
	from_port := object.get(port_range, "From", -1)
	to_port := object.get(port_range, "To", -1)
	admin_port := data.approved_admin_ports[_]
	from_port <= admin_port
	to_port >= admin_port
}

approved_admin_ipv4_cidr(cidr) if {
	approved := data.approved_admin_cidrs[_]
	net.cidr_contains(approved, cidr)
}

approved_admin_ipv6_cidr(cidr) if {
	approved := data.approved_admin_ipv6_cidrs[_]
	net.cidr_contains(approved, cidr)
}

admin_source_approved(entry) if {
	cidr := object.get(entry, "CidrBlock", "")
	cidr != ""
	approved_admin_ipv4_cidr(cidr)
}

admin_source_approved(entry) if {
	cidr := object.get(entry, "Ipv6CidrBlock", "")
	cidr != ""
	approved_admin_ipv6_cidr(cidr)
}

unapproved_admin_ingress[entry] if {
	some entry in input.network_acl.Entries
	not entry.Egress
	lower(entry.RuleAction) == "allow"
	entry_matches_admin_port(entry)
	not admin_source_approved(entry)
}

violation[{}] if {
	count(unapproved_admin_ingress) > 0
}

title := "Network ACL administrative ingress should be restricted to approved sources"
description := sprintf("Network ACL administrative ingress ports should be restricted to approved IPv4 sources: %s and approved IPv6 sources: %s for admin ports: %s", [concat(", ", data.approved_admin_cidrs), concat(", ", data.approved_admin_ipv6_cidrs), concat(", ", [sprintf("%v", [port]) | port := data.approved_admin_ports[_]])])
