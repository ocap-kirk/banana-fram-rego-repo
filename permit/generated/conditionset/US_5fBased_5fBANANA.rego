package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default resourceset_US_5fBased_5fBANANA = false

resourceset_US_5fBased_5fBANANA {
	attributes.resource.location == "US"
	attributes.resource.type == "Banana"
}
