package compliance_framework.restrict_admin_ingress

risk_templates := [{
	"name": "Network ACL allows administrative ingress from unapproved sources",
	"title": "Administrative access exposure through Network ACL ingress",
	"statement": "A Network ACL allows administrative ports from IPv4 or IPv6 sources outside the approved management ranges, exposing administrative access paths to unauthorized probing, brute-force attempts, and direct compromise opportunities.",
	"likelihood_hint": "high",
	"impact_hint": "high",
	"violation_ids": ["nacl_unapproved_admin_ingress"],
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
		"title": "Restrict administrative ingress to approved management sources",
		"description": "Limit Network ACL rules for administrative ports to the explicitly approved IPv4 and IPv6 management CIDRs.",
		"tasks": [
			{"title": "Identify ingress allow rules that cover approved administrative ports"},
			{"title": "Restrict those rules to the approved management IPv4 and IPv6 CIDRs"},
			{"title": "Remove direct public administrative access where it is not required"},
			{"title": "Validate that administrative access flows through approved management entry points"},
		],
	},
}]

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
	admin_port := data.approved_admin_ports[_] # regal ignore:unresolved-reference
	from_port <= admin_port
	to_port >= admin_port
}

approved_admin_ipv4_cidr(cidr) if {
	approved := data.approved_admin_cidrs[_] # regal ignore:unresolved-reference
	net.cidr_contains(approved, cidr)
}

approved_admin_ipv6_cidr(cidr) if {
	approved := data.approved_admin_ipv6_cidrs[_] # regal ignore:unresolved-reference
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

violation[{"id": "nacl_unapproved_admin_ingress"}] if {
	count(unapproved_admin_ingress) > 0
}

title := "Network ACL administrative ingress should be restricted to approved sources"
description := sprintf("Network ACL administrative ingress ports should be restricted to approved IPv4 sources: %s and approved IPv6 sources: %s for admin ports: %s", [concat(", ", data.approved_admin_cidrs), concat(", ", data.approved_admin_ipv6_cidrs), concat(", ", [sprintf("%v", [port]) | port := data.approved_admin_ports[_]])]) # regal ignore:unresolved-reference
