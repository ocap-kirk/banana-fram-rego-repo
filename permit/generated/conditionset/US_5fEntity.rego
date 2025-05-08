package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default resourceset_US_5fEntity = false

resourceset_US_5fEntity {
	attributes.resource.locaiton == attributes.user.locaiton
	attributes.resource.type == "Entity"
}
