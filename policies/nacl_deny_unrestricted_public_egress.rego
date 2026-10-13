package compliance_framework.deny_unrestricted_public_egress

risk_templates := [{
	"name": "Network ACL allows unrestricted public egress",
	"title": "Unrestricted public outbound access from Network ACL",
	"statement": "A Network ACL allows all-protocol or all-port egress to public IPv4 or IPv6 destinations, increasing the chance of uncontrolled outbound connectivity, command-and-control traffic, and data exfiltration paths from associated workloads.",
	"likelihood_hint": "high",
	"impact_hint": "high",
	"violation_ids": ["nacl_unrestricted_public_egress"],
	"threat_refs": [
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-284",
			"title": "Improper Access Control",
			"url": "https://cwe.mitre.org/data/definitions/284.html",
		},
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-668",
			"title": "Exposure of Resource to Wrong Sphere",
			"url": "https://cwe.mitre.org/data/definitions/668.html",
		},
	],
	"remediation": {
		"title": "Constrain public egress from the Network ACL",
		"description": "Replace unrestricted public egress rules with destination and port restrictions that match the approved outbound connectivity requirements for the associated subnets.",
		"tasks": [
			{"title": "Identify egress allow rules that permit all protocols or all ports to public destinations"},
			{"title": "Restrict egress to the minimum required ports, protocols, and destination ranges"},
			{"title": "Review whether internet-bound access should traverse approved egress controls or proxies instead"},
			{"title": "Validate that outbound paths still support the required workload behavior after restriction"},
		],
	},
}]

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

violation[{"id": "nacl_unrestricted_public_egress"}] if {
	count(unrestricted_public_egress) > 0
}

title := "Network ACL should not allow unrestricted public egress"
description := "Network ACL egress allow rules should avoid all-protocol or all-port access to public IPv4 or IPv6 destinations"
