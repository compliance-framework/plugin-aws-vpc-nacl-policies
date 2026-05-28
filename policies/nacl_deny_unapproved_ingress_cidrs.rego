package compliance_framework.deny_unapproved_ingress_cidrs

public_ipv4_cidr(cidr) if {
	net.cidr_contains(cidr, "0.0.0.0/0")
}

public_ipv6_cidr(cidr) if {
	net.cidr_contains(cidr, "::/0")
}

approved_public_ingress_port(port) if {
	approved := data.approved_nacl_public_ingress_ports[_]
	port == approved
}

entry_allows_public_source(entry) if {
	cidr := object.get(entry, "CidrBlock", "")
	cidr != ""
	public_ipv4_cidr(cidr)
}

entry_allows_public_source(entry) if {
	cidr := object.get(entry, "Ipv6CidrBlock", "")
	cidr != ""
	public_ipv6_cidr(cidr)
}

entry_allows_only_approved_public_ports(entry) if {
	port_range := object.get(entry, "PortRange", {})
	from_port := object.get(port_range, "From", -1)
	to_port := object.get(port_range, "To", -1)
	from_port == to_port
	approved_public_ingress_port(from_port)
}

unapproved_public_ingress[entry] if {
	some entry in input.network_acl.Entries
	not entry.Egress
	lower(entry.RuleAction) == "allow"
	entry_allows_public_source(entry)
	not entry_allows_only_approved_public_ports(entry)
}

violation[{}] if {
	count(unapproved_public_ingress) > 0
}

title := "Network ACL public ingress should be limited to approved ports"
description := sprintf("Network ACL ingress allow rules from public sources should only expose approved ports: %s", [concat(", ", [sprintf("%v", [port]) | port := data.approved_nacl_public_ingress_ports[_]])])
