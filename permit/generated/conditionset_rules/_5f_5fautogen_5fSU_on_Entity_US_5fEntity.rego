package permit.generated.conditionset.rules

import future.keywords.in

import data.permit.generated.abac.utils.attributes
import data.permit.generated.abac.utils.condition_set_permissions
import data.permit.generated.conditionset

default _5f5f_5f5fautogen_5f5fSU_5fon_5fEntity_5fUS_5f5fEntity = false

_5f5f_5f5fautogen_5f5fSU_5fon_5fEntity_5fUS_5f5fEntity {
	conditionset.userset__5f_5fautogen_5fSU
	conditionset.resourceset_US_5fEntity
	input.action in condition_set_permissions.__autogen_SU.US_Entity[input.resource.type]
}
