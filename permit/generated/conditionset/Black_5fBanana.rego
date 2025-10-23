package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default resourceset_Black_5fBanana = false

resourceset_Black_5fBanana {
	attributes.resource.color == "black"
	attributes.resource.location == attributes.user.location
	attributes.resource.type == "Banana"
}
