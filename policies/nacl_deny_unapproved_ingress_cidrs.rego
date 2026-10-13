package compliance_framework.deny_unapproved_ingress_cidrs

risk_templates := [{
	"name": "Network ACL allows unapproved public ingress",
	"title": "Public network exposure through Network ACL ingress",
	"statement": "A Network ACL allows ingress from public IPv4 or IPv6 ranges on ports outside the approved public service baseline, increasing the chance of unauthorized access, scanning, and unintended exposure of workloads behind the ACL.",
	"likelihood_hint": "high",
	"impact_hint": "high",
	"violation_ids": ["nacl_unapproved_public_ingress"],
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
		"title": "Restrict public ingress to approved ports",
		"description": "Limit public Network ACL ingress rules to the explicitly approved service ports and remove broader public exposure from the ACL.",
		"tasks": [
			{"title": "Review public IPv4 and IPv6 ingress allow rules on the Network ACL"},
			{"title": "Remove public ingress rules that expose unapproved ports or broad port ranges"},
			{"title": "Constrain any required public services to the approved port baseline"},
			{"title": "Confirm direct public reachability is necessary for the associated subnets"},
		],
	},
}]

non_public_ipv4_cidrs := [
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
]

non_public_ipv6_cidrs := [
	"::/128",
	"::1/128",
	"::ffff:0:0/96",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"100::/64",
	"2001::/32",
	"2001:2::/48",
	"2001:10::/28",
	"2001:20::/28",
	"2001:db8::/32",
	"2002::/16",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
]

non_public_ipv4_cidr(cidr) if {
	non_public := non_public_ipv4_cidrs[_]
	net.cidr_contains(non_public, cidr)
}

non_public_ipv6_cidr(cidr) if {
	non_public := non_public_ipv6_cidrs[_]
	net.cidr_contains(non_public, cidr)
}

public_ipv4_cidr(cidr) if {
	not non_public_ipv4_cidr(cidr)
}

public_ipv6_cidr(cidr) if {
	not non_public_ipv6_cidr(cidr)
}

approved_public_ingress_port(port) if {
	approved := data.approved_nacl_public_ingress_ports[_] # regal ignore:unresolved-reference
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

violation[{"id": "nacl_unapproved_public_ingress"}] if {
	count(unapproved_public_ingress) > 0
}

title := "Network ACL public ingress should be limited to approved ports"
description := sprintf("Network ACL ingress allow rules from public sources should only expose approved ports: %s", [concat(", ", [sprintf("%v", [port]) | port := data.approved_nacl_public_ingress_ports[_]])]) # regal ignore:unresolved-reference
