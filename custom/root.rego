package permit.custom

import data.permit.utils.rebac
import data.permit.generated.abac.utils.attributes
import future.keywords.in

default allow := false

# Custom rule to check if user has a specific ReBAC role
has_rebac_role(role_type, role_name) {
    some role in rebac.rebac_roles
    startswith(role, role_type)
    role_parts := split(role, "#")
    count(role_parts) == 2
    role_parts[1] == role_name
}

# Custom rule to check if user has a specific ABAC attribute
has_abac_attribute(attribute_name, attribute_value) {
    attributes.user[attribute_name] == attribute_value
}

# Get parent resources using relationships data
get_parent_resources(resource_type, resource_key) := parents {
    # Get parent relationships from the relationships data
    resource_id := sprintf("%s:%s", [resource_type, resource_key])
    parent_rels := data.relationships[resource_id]["relation:parent"]
    parents := {{"type": type, "key": key} |
        some type, keys in parent_rels
        key := keys[_]
    }
} else := {} {
    true
}

# Get attributes for a specific resource
get_resource_attributes(resource_type, resource_key) := attrs {
    resource_id := sprintf("%s:%s", [resource_type, resource_key])
    attrs := data.resource_instances[resource_id].attributes
} else := {} {
    true
}

# Get all attributes including inherited ones
get_all_attributes(resource_type, resource_key) := all_attrs {
    # Get the resource's own attributes
    own_attrs := get_resource_attributes(resource_type, resource_key)
    
    # Get parent resources and their attributes
    parents := get_parent_resources(resource_type, resource_key)
    
    # If there are no parents, just return own attributes
    all_attrs := own_attrs
} else := {} {
    true
}

get_all_attributes(resource_type, resource_key) := all_attrs {
    # Get the resource's own attributes
    own_attrs := get_resource_attributes(resource_type, resource_key)
    
    # Get parent resources and their attributes
    parents := get_parent_resources(resource_type, resource_key)
    
    # Get parent attributes recursively and merge them
    parent_attrs := object.union_n([
        get_all_attributes(parent.type, parent.key) |
        parent := parents[_]
    ])
    
    # Merge all attributes, with child attributes taking precedence
    all_attrs := object.union(own_attrs, parent_attrs)
} {
    # Only apply this rule if there are parents
    parents := get_parent_resources(resource_type, resource_key)
    count(parents) > 0
}

# Debug information
debug_info := {
    "resource_parents": get_parent_resources(input.resource.type, input.resource.key),
    "resource_attrs": get_resource_attributes(input.resource.type, input.resource.key),
    "all_attrs": get_all_attributes(input.resource.type, input.resource.key),
    "relationships": data.relationships[sprintf("%s:%s", [input.resource.type, input.resource.key])],
    "farm_attrs": get_resource_attributes("Farm", "ManzanoFarm"),
    "tree_attrs": get_resource_attributes("Tree", "tree_001"),
    "banana_attrs": get_resource_attributes("Banana", "ba_001"),
    "parent_tree_attrs": get_all_attributes("Tree", "tree_001"),
    "parent_farm_attrs": get_all_attributes("Farm", "ManzanoFarm")
}

# Allow eating bananas only if they are in the US (either directly or through inheritance)
allow {
    # Check if the action is "eat" and the resource is a banana
    input.action == "eat"
    input.resource.type == "Banana"
    
    # Get all attributes including inherited ones
    all_attrs := get_all_attributes(input.resource.type, input.resource.key)
    
    # Check if location is US either directly or through inheritance
    all_attrs.location == "US"
}

# You can find the official Rego tutorial at:
# https://www.openpolicyagent.org/docs/latest/policy-language/
