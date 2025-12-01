package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default userset__5f_5fautogen_5fmember = false

userset__5f_5fautogen_5fmember {
	"member" in attributes.user.roles
}
