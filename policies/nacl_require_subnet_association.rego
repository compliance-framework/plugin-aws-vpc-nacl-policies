package compliance_framework.require_subnet_association

has_subnet_association if {
	count(input.network_acl.Associations) > 0
}

violation[{}] if {
	not data.allow_unassociated_nacl # regal ignore:unresolved-reference
	not has_subnet_association
}

title := "Network ACL should be associated with at least one subnet"
description := "Network ACLs should have at least one subnet association unless unassociated Network ACLs are explicitly allowed by policy data"
