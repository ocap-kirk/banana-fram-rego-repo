package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default userset_Finance_5fViewer = false

userset_Finance_5fViewer {
	attributes.user.Finance_Viewer == true
}
