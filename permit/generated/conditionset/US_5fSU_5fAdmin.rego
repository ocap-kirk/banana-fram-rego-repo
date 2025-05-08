package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default userset_US_5fSU_5fAdmin = false

userset_US_5fSU_5fAdmin {
	"SU" in attributes.user.roles
	attributes.user.locaiton == "US"
}
