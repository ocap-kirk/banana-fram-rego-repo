package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default userset_US_5fAdmin = false

userset_US_5fAdmin {
	attributes.user.roles == "admin"
	attributes.user.location == "US"
}
