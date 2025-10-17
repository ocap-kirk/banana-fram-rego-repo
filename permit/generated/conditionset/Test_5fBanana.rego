package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default resourceset_Test_5fBanana = false

resourceset_Test_5fBanana {
	attributes.resource.color == "green"
	attributes.resource.type == "Banana"
}
