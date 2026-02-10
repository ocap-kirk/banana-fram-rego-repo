package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default userset_German_5fAdmin = false

userset_German_5fAdmin {
	attributes.user.location == "DE"
}
