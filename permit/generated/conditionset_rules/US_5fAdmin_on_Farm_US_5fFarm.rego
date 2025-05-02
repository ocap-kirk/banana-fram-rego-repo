package permit.generated.conditionset.rules

import future.keywords.in

import data.permit.generated.abac.utils.attributes
import data.permit.generated.abac.utils.condition_set_permissions
import data.permit.generated.conditionset

default US_5f5fAdmin_5fon_5fFarm_5fUS_5f5fFarm = false

US_5f5fAdmin_5fon_5fFarm_5fUS_5f5fFarm {
	conditionset.userset_US_5fAdmin
	conditionset.resourceset_US_5fFarm
	input.action in condition_set_permissions.US_Admin.US_Farm[input.resource.type]
}
