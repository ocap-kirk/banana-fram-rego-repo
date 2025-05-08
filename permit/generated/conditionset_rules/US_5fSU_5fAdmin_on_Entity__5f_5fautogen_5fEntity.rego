package permit.generated.conditionset.rules

import future.keywords.in

import data.permit.generated.abac.utils.attributes
import data.permit.generated.abac.utils.condition_set_permissions
import data.permit.generated.conditionset

default US_5f5fSU_5f5fAdmin_5fon_5fEntity_5f_5f5f_5f5fautogen_5f5fEntity = false

US_5f5fSU_5f5fAdmin_5fon_5fEntity_5f_5f5f_5f5fautogen_5f5fEntity {
	conditionset.userset_US_5fSU_5fAdmin
	conditionset.resourceset__5f_5fautogen_5fEntity
	input.action in condition_set_permissions.US_SU_Admin.__autogen_Entity[input.resource.type]
}
