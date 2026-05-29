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
      "url": "https://cwe.mitre.org/data/definitions/284.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-668",
      "title": "Exposure of Resource to Wrong Sphere",
      "url": "https://cwe.mitre.org/data/definitions/668.html"
    }
  ],
  "remediation": {
    "title": "Restrict public ingress to approved ports",
    "description": "Limit public Network ACL ingress rules to the explicitly approved service ports and remove broader public exposure from the ACL.",
    "tasks": [
      {"title": "Review public IPv4 and IPv6 ingress allow rules on the Network ACL"},
      {"title": "Remove public ingress rules that expose unapproved ports or broad port ranges"},
      {"title": "Constrain any required public services to the approved port baseline"},
      {"title": "Confirm direct public reachability is necessary for the associated subnets"}
    ]
  }
}]

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

violation[{"id": "nacl_unapproved_public_ingress"}] if {
	count(unapproved_public_ingress) > 0
}

title := "Network ACL public ingress should be limited to approved ports"
description := sprintf("Network ACL ingress allow rules from public sources should only expose approved ports: %s", [concat(", ", [sprintf("%v", [port]) | port := data.approved_nacl_public_ingress_ports[_]])])
