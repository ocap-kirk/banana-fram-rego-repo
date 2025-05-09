package permit.generated.conditionset.rules

import future.keywords.in

import data.permit.generated.abac.utils.attributes
import data.permit.generated.abac.utils.condition_set_permissions
import data.permit.generated.conditionset

default _5f5f_5f5fautogen_5f5fstandard_5f5fuser_5fon_5fBanana_5fNew = false

_5f5f_5f5fautogen_5f5fstandard_5f5fuser_5fon_5fBanana_5fNew {
	conditionset.userset__5f_5fautogen_5fstandard_5fuser
	conditionset.resourceset_New
	input.action in condition_set_permissions.__autogen_standard_user.New[input.resource.type]
}
