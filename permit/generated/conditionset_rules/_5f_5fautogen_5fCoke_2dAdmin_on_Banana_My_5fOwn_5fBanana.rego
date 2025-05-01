package permit.generated.conditionset.rules

import future.keywords.in

import data.permit.generated.abac.utils.attributes
import data.permit.generated.abac.utils.condition_set_permissions
import data.permit.generated.conditionset

default _5f5f_5f5fautogen_5f5fCoke_5f2dAdmin_5fon_5fBanana_5fMy_5f5fOwn_5f5fBanana = false

_5f5f_5f5fautogen_5f5fCoke_5f2dAdmin_5fon_5fBanana_5fMy_5f5fOwn_5f5fBanana {
	conditionset.userset__5f_5fautogen_5fCoke_2dAdmin
	conditionset.resourceset_My_5fOwn_5fBanana
	input.action in condition_set_permissions["__autogen_Coke-Admin"].My_Own_Banana[input.resource.type]
}
