package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default resourceset_My_5fOwn_5fBanana = false

resourceset_My_5fOwn_5fBanana {
	attributes.resource.ownerid == attributes.user.key
	attributes.resource.type == "Banana"
}
