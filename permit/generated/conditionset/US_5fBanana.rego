package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default resourceset_US_5fBanana = false

resourceset_US_5fBanana {
	attributes.resource.location == "US"
	attributes.resource.type == "Banana"
}
