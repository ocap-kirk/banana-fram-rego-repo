package permit.generated.conditionset.rules

import future.keywords.in

import data.permit.generated.abac.utils.attributes
import data.permit.generated.abac.utils.condition_set_permissions
import data.permit.generated.conditionset

default US_5f5fAdmin_5fon_5fBanana_5fMy_5f5fOwn_5f5fBanana = false

US_5f5fAdmin_5fon_5fBanana_5fMy_5f5fOwn_5f5fBanana {
	conditionset.userset_US_5fAdmin
	conditionset.resourceset_My_5fOwn_5fBanana
	input.action in condition_set_permissions.US_Admin.My_Own_Banana[input.resource.type]
}
