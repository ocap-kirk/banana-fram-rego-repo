package permit.custom

import data.permit.user_permissions
import future.keywords.in

default allow := false

# You can find the official Rego tutorial at:
# https://www.openpolicyagent.org/docs/latest/policy-language/
# Example rule - you can replace this with something of your own
# allow {
# 	input.user.key == "test@permit.io"
# }
# Also, you can add more allow blocks here to get an OR effect
# allow {
#     # i.e if you add my_custom_rule here - the policy will allow
#     # if my_custom_rule is true, EVEN IF policies.allow is false.
#     my_custom_rule
# }

# Custom User Permissions
# Define custom_user_permissions to contribute additional permissions
# to the get_user_permissions API response.
#
# Each entry must be an object mapping a resource key to its permission details:
#   { "resource_type:resource_key": {
#       "resource": {"key": "...", "type": "...", "attributes": {}},
#       "permissions": {"resource_type:action", ...},
#       "roles": ["role_name", ...],
#       "tenant": {"key": "...", "type": "__tenant"}
#   }}
#
# Example:
custom_user_permissions[p] {
    input.user.key == "special-user"
    p := {"special-resource:doc1": {
        "resource": {"key": "doc1", "type": "special-resource", "attributes": {}},
        "permissions": {"special-resource:read", "special-resource:write"},
        "roles": ["custom-role"],
        "tenant": {"key": "default", "type": "__tenant"},
    }}
}

# Merged permissions: standard Permit permissions + custom permissions
# Query via OPA: POST /v1/data/permit/custom/permissions
permissions[key] := value {
    # Include all standard permissions
    value := user_permissions.permissions[key]
}

permissions[key] := value {
    # Include custom permissions
    some entry in custom_user_permissions
    some key, details in entry
    value := details
}
