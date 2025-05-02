package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default resourceset_US_5fFarm = false

resourceset_US_5fFarm {
	attributes.resource.location == "US"
	attributes.resource.type == "Farm"
}
