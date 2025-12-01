package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default userset_MFA_5fVerified_5fAdmin = false

userset_MFA_5fVerified_5fAdmin {
	"admin" in attributes.user.roles
	attributes.user.mfa_verified == true
}
