package permit.custom

import data.permit.utils.rebac
import data.permit.generated.abac.utils.attributes
import future.keywords.in

# Get parent resources using relationships data
get_parent_resources(resource_type, resource_key) := parents {
    # Get parent relationships from the relationships data
    resource_parts := rebac.split_resource_to_parts(sprintf("%s:%s", [resource_type, resource_key]))
    parent_rels := data.relationships[resource_parts.fully_qualified_key]["relation:parent"]
    parents := {{"type": type, "key": key} |
        some type, keys in parent_rels
        key := keys[_]
    }
} else := {} {
    true
}

# Get attributes for a specific resource
get_resource_attributes(resource_type, resource_key) := attrs {
    resource_parts := rebac.split_resource_to_parts(sprintf("%s:%s", [resource_type, resource_key]))
    attrs := data.resource_instances[resource_parts.fully_qualified_key].attributes
} else := {} {
    true
}

# Get all attributes including inherited ones (traversing full hierarchy)
get_all_attributes(resource_type, resource_key) := all_attrs {
    # Get the resource's own attributes
    own_attrs := get_resource_attributes(resource_type, resource_key)
    
    # Get parent resources
    parents := get_parent_resources(resource_type, resource_key)
    
    # Get attributes from all parents in the hierarchy
    parent_attrs := object.union_n([
        # Get direct parent attributes
        get_resource_attributes(parent.type, parent.key) |
        parent := parents[_]
    ])
    
    # Get grandparent attributes (if any)
    grandparent_attrs := object.union_n([
        get_resource_attributes(grandparent.type, grandparent.key) |
        parent := parents[_]
        grandparent := get_parent_resources(parent.type, parent.key)[_]
    ])
    
    # Merge all attributes, with child attributes taking precedence
    all_attrs := object.union(object.union(own_attrs, parent_attrs), grandparent_attrs)
} else := {} {
    true
}

# Debug information
debug_info := {
    "resource_parents": get_parent_resources(input.resource.type, input.resource.key),
    "resource_attrs": get_resource_attributes(input.resource.type, input.resource.key),
    "all_attrs": get_all_attributes(input.resource.type, input.resource.key),
    "relationships": data.relationships[rebac.split_resource_to_parts(sprintf("%s:%s", [input.resource.type, input.resource.key])).fully_qualified_key],
    "farm_attrs": get_resource_attributes("Farm", "ManzanoFarm"),
    "tree_attrs": get_resource_attributes("Tree", "tree_001"),
    "banana_attrs": get_resource_attributes("Banana", "ba_001"),
    "parent_tree_attrs": get_all_attributes("Tree", "tree_001"),
    "parent_farm_attrs": get_all_attributes("Farm", "ManzanoFarm")
}

# Print debug information to OPA log
debug_print {
    print("Resource Parents:", get_parent_resources(input.resource.type, input.resource.key))
    print("Resource Attributes:", get_resource_attributes(input.resource.type, input.resource.key))
    print("All Attributes:", get_all_attributes(input.resource.type, input.resource.key))
    print("Debug Info:", debug_info)
}

# Map all inherited attributes to resource attributes
custom_resource_attributes := get_all_attributes(input.resource.type, input.resource.key)
