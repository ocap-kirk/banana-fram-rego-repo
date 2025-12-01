package permit.custom

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

# MFA requirement - customize conditions as needed
default mfa_required := false

# Example: require MFA for delete actions
# mfa_required {
#     input.action == "delete"
# }

# Example: require MFA for sensitive resource types
# mfa_required {
#     input.resource.type == "FinancialRecord"
# }
