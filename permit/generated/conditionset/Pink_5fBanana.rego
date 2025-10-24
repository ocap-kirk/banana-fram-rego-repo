package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default resourceset_Pink_5fBanana = false

resourceset_Pink_5fBanana {
	attributes.resource.color == "pink"
	attributes.resource.type == "Banana"
}
