package compliance_framework.deny_unrestricted_public_egress

public_ipv4_cidr(cidr) if {
	net.cidr_contains(cidr, "0.0.0.0/0")
}

public_ipv6_cidr(cidr) if {
	net.cidr_contains(cidr, "::/0")
}

public_destination(entry) if {
	cidr := object.get(entry, "CidrBlock", "")
	cidr != ""
	public_ipv4_cidr(cidr)
}

public_destination(entry) if {
	cidr := object.get(entry, "Ipv6CidrBlock", "")
	cidr != ""
	public_ipv6_cidr(cidr)
}

all_protocols(entry) if {
	object.get(entry, "Protocol", "-1") == "-1"
}

all_ports(entry) if {
	all_protocols(entry)
}

all_ports(entry) if {
	port_range := object.get(entry, "PortRange", {})
	from_port := object.get(port_range, "From", -1)
	to_port := object.get(port_range, "To", -1)
	from_port == 0
	to_port == 65535
}

unrestricted_public_egress[entry] if {
	some entry in input.network_acl.Entries
	entry.Egress == true
	lower(entry.RuleAction) == "allow"
	public_destination(entry)
	all_ports(entry)
}

violation[{}] if {
	count(unrestricted_public_egress) > 0
}

title := "Network ACL should not allow unrestricted public egress"
description := "Network ACL egress allow rules should avoid all-protocol or all-port access to public IPv4 or IPv6 destinations"
