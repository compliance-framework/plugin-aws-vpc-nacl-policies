package compliance_framework.require_tags

required_tag[tag] if {
	tag := data.required_nacl_tags[_] # regal ignore:unresolved-reference
}

missing_tag[tag] if {
	required_tag[tag]
	not tag_exists(input.network_acl.Tags, tag)
}

violation[{}] if {
	count(missing_tag) > 0
}

tag_exists(tags, tag_name) if {
	some tag in tags
	lower(tag.Key) == lower(tag_name)
}

title := "Network ACL should set required tags"
description := sprintf("Network ACL tags should contain required tag keys: %s", [concat(", ", data.required_nacl_tags)]) # regal ignore:unresolved-reference
