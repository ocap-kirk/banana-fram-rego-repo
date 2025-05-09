package permit.generated.conditionset.rules

import future.keywords.in

import data.permit.generated.abac.utils.attributes
import data.permit.generated.abac.utils.condition_set_permissions
import data.permit.generated.conditionset

default US_5f5fAdmin_5fon_5fBanana_5fNew = false

US_5f5fAdmin_5fon_5fBanana_5fNew {
	conditionset.userset_US_5fAdmin
	conditionset.resourceset_New
	input.action in condition_set_permissions.US_Admin.New[input.resource.type]
}
