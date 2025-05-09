package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default resourceset_New = false

resourceset_New {
	attributes.resource.color == "black"
	attributes.resource.type == "Banana"
}
