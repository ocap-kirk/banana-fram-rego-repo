package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default userset__5f_5fautogen_5fFinance_5fread = false

userset__5f_5fautogen_5fFinance_5fread {
	"Finance_read" in attributes.user.roles
}
