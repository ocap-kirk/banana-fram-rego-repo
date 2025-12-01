package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default userset_MFA_5fVerified = false

userset_MFA_5fVerified {
	attributes.user.mfa_verified == true
}
