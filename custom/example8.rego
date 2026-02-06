package permit.custom.example8

import rego.v1

# ============================================================================
# RBAC (Role-Based Access Control) Rules
# ============================================================================

# Default deny - explicit allow required
default allow = false

# Allow if user has admin role
allow if {
	input.user.role == "admin"
}

# Allow if user is the resource owner
allow if {
	input.user.id == input.resource.owner_id
}

# Allow based on specific permissions
allow if {
	some permission in input.user.permissions
	permission == required_permission
}

# Required permission based on action
required_permission := "read" if {
	input.action == "view"
}

required_permission := "write" if {
	input.action in ["create", "update", "delete"]
}

required_permission := "admin" if {
	input.action == "manage"
}

# ============================================================================
# User Management Rules
# ============================================================================

# Check if user can create other users
can_create_user if {
	input.user.role == "admin"
}

can_create_user if {
	input.user.role == "manager"
	input.target_user.role != "admin"
}

# Check if user can delete other users
can_delete_user if {
	input.user.role == "admin"
}

can_delete_user if {
	input.user.role == "manager"
	not input.target_user.role in ["admin", "manager"]
}

# Check if user can update other users
can_update_user if {
	input.user.role == "admin"
}

can_update_user if {
	input.user.id == input.target_user.id
}

can_update_user if {
	input.user.role == "manager"
	input.target_user.role == "user"
}

# Check if user can view other users
can_view_user if {
	input.user.role in ["admin", "manager"]
}

can_view_user if {
	input.user.id == input.target_user.id
}

can_view_user if {
	input.target_user.id in input.user.team_members
}

# ============================================================================
# Resource Access Rules
# ============================================================================

# Check document access
can_access_document if {
	input.user.role == "admin"
}

can_access_document if {
	input.document.owner_id == input.user.id
}

can_access_document if {
	some share in input.document.shared_with
	share.user_id == input.user.id
	share.permission in ["read", "write", "admin"]
}

can_access_document if {
	input.document.public == true
	input.action == "read"
}

can_access_document if {
	input.user.department == input.document.department
	input.document.department_access == true
}

# Check if user can edit document
can_edit_document if {
	input.user.role == "admin"
}

can_edit_document if {
	input.document.owner_id == input.user.id
}

can_edit_document if {
	some share in input.document.shared_with
	share.user_id == input.user.id
	share.permission in ["write", "admin"]
}

# Check if user can delete document
can_delete_document if {
	input.user.role == "admin"
}

can_delete_document if {
	input.document.owner_id == input.user.id
}

can_delete_document if {
	some share in input.document.shared_with
	share.user_id == input.user.id
	share.permission == "admin"
}

# Check if user can share document
can_share_document if {
	input.user.role == "admin"
}

can_share_document if {
	input.document.owner_id == input.user.id
}

can_share_document if {
	some share in input.document.shared_with
	share.user_id == input.user.id
	share.permission == "admin"
}

# ============================================================================
# Project Management Rules
# ============================================================================

# Check project access
can_access_project if {
	input.user.role == "admin"
}

can_access_project if {
	input.project.owner_id == input.user.id
}

can_access_project if {
	some member in input.project.members
	member.user_id == input.user.id
}

can_access_project if {
	input.user.department == input.project.department
	input.project.department_wide == true
}

# Check if user can create project
can_create_project if {
	input.user.role in ["admin", "manager", "project_lead"]
}

can_create_project if {
	"create_project" in input.user.permissions
}

# Check if user can update project
can_update_project if {
	input.user.role == "admin"
}

can_update_project if {
	input.project.owner_id == input.user.id
}

can_update_project if {
	some member in input.project.members
	member.user_id == input.user.id
	member.role in ["admin", "editor"]
}

# Check if user can delete project
can_delete_project if {
	input.user.role == "admin"
}

can_delete_project if {
	input.project.owner_id == input.user.id
}

# Check if user can add members to project
can_add_project_member if {
	input.user.role == "admin"
}

can_add_project_member if {
	input.project.owner_id == input.user.id
}

can_add_project_member if {
	some member in input.project.members
	member.user_id == input.user.id
	member.role == "admin"
}

# Check if user can remove members from project
can_remove_project_member if {
	input.user.role == "admin"
}

can_remove_project_member if {
	input.project.owner_id == input.user.id
}

can_remove_project_member if {
	some member in input.project.members
	member.user_id == input.user.id
	member.role == "admin"
	input.target_member.role != "admin"
}

# ============================================================================
# Task Management Rules
# ============================================================================

# Check task access
can_access_task if {
	input.user.role == "admin"
}

can_access_task if {
	input.task.assignee_id == input.user.id
}

can_access_task if {
	input.task.creator_id == input.user.id
}

can_access_task if {
	can_access_project
	input.task.project_id == input.project.id
}

# Check if user can create task
can_create_task if {
	input.user.role in ["admin", "manager", "project_lead", "developer"]
}

can_create_task if {
	can_access_project
	input.task.project_id == input.project.id
}

# Check if user can update task
can_update_task if {
	input.user.role == "admin"
}

can_update_task if {
	input.task.assignee_id == input.user.id
}

can_update_task if {
	input.task.creator_id == input.user.id
}

can_update_task if {
	can_update_project
	input.task.project_id == input.project.id
}

# Check if user can delete task
can_delete_task if {
	input.user.role == "admin"
}

can_delete_task if {
	input.task.creator_id == input.user.id
}

can_delete_task if {
	can_delete_project
	input.task.project_id == input.project.id
}

# Check if user can assign task
can_assign_task if {
	input.user.role in ["admin", "manager", "project_lead"]
}

can_assign_task if {
	input.task.assignee_id == input.user.id
}

can_assign_task if {
	can_update_project
	input.task.project_id == input.project.id
}

# ============================================================================
# Organization and Department Rules
# ============================================================================

# Check organization access
can_access_organization if {
	input.user.role == "admin"
}

can_access_organization if {
	input.user.organization_id == input.organization.id
}

# Check if user can manage organization
can_manage_organization if {
	input.user.role == "admin"
}

can_manage_organization if {
	input.user.organization_id == input.organization.id
	input.user.org_role == "owner"
}

can_manage_organization if {
	input.user.organization_id == input.organization.id
	input.user.org_role == "admin"
}

# Check department access
can_access_department if {
	input.user.role == "admin"
}

can_access_department if {
	input.user.department == input.department.name
}

can_access_department if {
	input.user.id == input.department.manager_id
}

# Check if user can manage department
can_manage_department if {
	input.user.role == "admin"
}

can_manage_department if {
	input.user.id == input.department.manager_id
}

can_manage_department if {
	input.user.department == input.department.name
	input.user.department_role == "admin"
}

# ============================================================================
# Team Management Rules
# ============================================================================

# Check team access
can_access_team if {
	input.user.role == "admin"
}

can_access_team if {
	input.user.id in input.team.member_ids
}

can_access_team if {
	input.user.id == input.team.lead_id
}

can_access_team if {
	input.user.department == input.team.department
}

# Check if user can create team
can_create_team if {
	input.user.role in ["admin", "manager"]
}

can_create_team if {
	"create_team" in input.user.permissions
}

# Check if user can update team
can_update_team if {
	input.user.role == "admin"
}

can_update_team if {
	input.user.id == input.team.lead_id
}

can_update_team if {
	input.user.id in input.team.admin_ids
}

# Check if user can delete team
can_delete_team if {
	input.user.role == "admin"
}

can_delete_team if {
	input.user.id == input.team.lead_id
}

# Check if user can add team members
can_add_team_member if {
	input.user.role in ["admin", "manager"]
}

can_add_team_member if {
	input.user.id == input.team.lead_id
}

can_add_team_member if {
	input.user.id in input.team.admin_ids
}

# Check if user can remove team members
can_remove_team_member if {
	input.user.role == "admin"
}

can_remove_team_member if {
	input.user.id == input.team.lead_id
}

can_remove_team_member if {
	input.user.id in input.team.admin_ids
	not input.target_user.id in input.team.admin_ids
}

# ============================================================================
# File and Folder Rules
# ============================================================================

# Check file access
can_access_file if {
	input.user.role == "admin"
}

can_access_file if {
	input.file.owner_id == input.user.id
}

can_access_file if {
	some permission in input.file.permissions
	permission.user_id == input.user.id
	permission.access in ["read", "write", "admin"]
}

can_access_file if {
	input.file.public == true
}

can_access_file if {
	can_access_folder
	input.file.folder_id == input.folder.id
}

# Check if user can upload file
can_upload_file if {
	input.user.role in ["admin", "manager", "user"]
}

can_upload_file if {
	input.user.storage_quota > input.user.storage_used + input.file.size
}

can_upload_file if {
	can_access_folder
	input.file.folder_id == input.folder.id
}

# Check if user can download file
can_download_file if {
	can_access_file
}

# Check if user can edit file
can_edit_file if {
	input.user.role == "admin"
}

can_edit_file if {
	input.file.owner_id == input.user.id
}

can_edit_file if {
	some permission in input.file.permissions
	permission.user_id == input.user.id
	permission.access in ["write", "admin"]
}

# Check if user can delete file
can_delete_file if {
	input.user.role == "admin"
}

can_delete_file if {
	input.file.owner_id == input.user.id
}

can_delete_file if {
	some permission in input.file.permissions
	permission.user_id == input.user.id
	permission.access == "admin"
}

# Check folder access
can_access_folder if {
	input.user.role == "admin"
}

can_access_folder if {
	input.folder.owner_id == input.user.id
}

can_access_folder if {
	some permission in input.folder.permissions
	permission.user_id == input.user.id
	permission.access in ["read", "write", "admin"]
}

can_access_folder if {
	input.folder.public == true
}

# Check if user can create folder
can_create_folder if {
	input.user.role in ["admin", "manager", "user"]
}

can_create_folder if {
	can_access_folder
	input.new_folder.parent_id == input.folder.id
}

# Check if user can update folder
can_update_folder if {
	input.user.role == "admin"
}

can_update_folder if {
	input.folder.owner_id == input.user.id
}

can_update_folder if {
	some permission in input.folder.permissions
	permission.user_id == input.user.id
	permission.access in ["write", "admin"]
}

# Check if user can delete folder
can_delete_folder if {
	input.user.role == "admin"
}

can_delete_folder if {
	input.folder.owner_id == input.user.id
}

can_delete_folder if {
	some permission in input.folder.permissions
	permission.user_id == input.user.id
	permission.access == "admin"
}

# ============================================================================
# API Access Rules
# ============================================================================

# Check API access
can_access_api if {
	input.user.role == "admin"
}

can_access_api if {
	input.user.api_enabled == true
}

can_access_api if {
	some key in input.user.api_keys
	key.key == input.api_key
	key.enabled == true
	time.now_ns() < key.expires_at
}

# Check API rate limits
api_rate_limit_exceeded if {
	input.user.api_calls_per_minute > input.user.rate_limit
}

api_rate_limit_exceeded if {
	input.user.api_calls_per_hour > input.user.hourly_rate_limit
}

# Check API endpoint access
can_access_endpoint if {
	input.user.role == "admin"
}

can_access_endpoint if {
	some scope in input.api_key.scopes
	scope == required_scope
}

# Required scope based on endpoint
required_scope := "read" if {
	input.endpoint.method == "GET"
}

required_scope := "write" if {
	input.endpoint.method in ["POST", "PUT", "PATCH"]
}

required_scope := "delete" if {
	input.endpoint.method == "DELETE"
}

required_scope := "admin" if {
	startswith(input.endpoint.path, "/admin/")
}

# ============================================================================
# Billing and Subscription Rules
# ============================================================================

# Check billing access
can_access_billing if {
	input.user.role == "admin"
}

can_access_billing if {
	input.user.organization_id == input.organization.id
	input.user.org_role in ["owner", "billing_admin"]
}

# Check if user can view invoices
can_view_invoices if {
	can_access_billing
}

# Check if user can download invoices
can_download_invoices if {
	can_access_billing
}

# Check if user can update payment method
can_update_payment_method if {
	input.user.role == "admin"
}

can_update_payment_method if {
	input.user.organization_id == input.organization.id
	input.user.org_role in ["owner", "billing_admin"]
}

# Check if user can cancel subscription
can_cancel_subscription if {
	input.user.role == "admin"
}

can_cancel_subscription if {
	input.user.organization_id == input.organization.id
	input.user.org_role == "owner"
}

# Check if user can upgrade subscription
can_upgrade_subscription if {
	can_update_payment_method
}

# Check if user can downgrade subscription
can_downgrade_subscription if {
	can_cancel_subscription
}

# ============================================================================
# Audit Log Rules
# ============================================================================

# Check audit log access
can_access_audit_logs if {
	input.user.role == "admin"
}

can_access_audit_logs if {
	"view_audit_logs" in input.user.permissions
}

can_access_audit_logs if {
	input.user.organization_id == input.organization.id
	input.user.org_role in ["owner", "compliance_admin"]
}

# Check if user can export audit logs
can_export_audit_logs if {
	input.user.role == "admin"
}

can_export_audit_logs if {
	input.user.organization_id == input.organization.id
	input.user.org_role in ["owner", "compliance_admin"]
}

# Check if user can view specific audit log entry
can_view_audit_log_entry if {
	can_access_audit_logs
}

can_view_audit_log_entry if {
	input.audit_log.user_id == input.user.id
}

# ============================================================================
# Notification Rules
# ============================================================================

# Check if user should receive notification
should_receive_notification if {
	input.user.notifications_enabled == true
}

should_receive_notification if {
	input.notification.type == "critical"
}

should_receive_notification if {
	input.notification.type in input.user.notification_preferences
}

# Check if user can manage notifications
can_manage_notifications if {
	input.user.id == input.target_user.id
}

can_manage_notifications if {
	input.user.role == "admin"
}

# Check if user can send notifications
can_send_notification if {
	input.user.role in ["admin", "manager"]
}

can_send_notification if {
	"send_notifications" in input.user.permissions
}

# ============================================================================
# Settings and Configuration Rules
# ============================================================================

# Check if user can access settings
can_access_settings if {
	input.user.role == "admin"
}

can_access_settings if {
	input.user.id == input.target_user.id
	input.settings.scope == "user"
}

can_access_settings if {
	input.user.organization_id == input.organization.id
	input.user.org_role in ["owner", "admin"]
	input.settings.scope == "organization"
}

# Check if user can update settings
can_update_settings if {
	can_access_settings
}

# Check if user can reset settings
can_reset_settings if {
	input.user.role == "admin"
}

can_reset_settings if {
	input.user.id == input.target_user.id
	input.settings.scope == "user"
}

# ============================================================================
# Webhook Rules
# ============================================================================

# Check webhook access
can_access_webhooks if {
	input.user.role == "admin"
}

can_access_webhooks if {
	input.user.organization_id == input.organization.id
	input.user.org_role in ["owner", "admin"]
}

can_access_webhooks if {
	input.webhook.creator_id == input.user.id
}

# Check if user can create webhook
can_create_webhook if {
	input.user.role in ["admin", "manager"]
}

can_create_webhook if {
	"manage_webhooks" in input.user.permissions
}

# Check if user can update webhook
can_update_webhook if {
	input.user.role == "admin"
}

can_update_webhook if {
	input.webhook.creator_id == input.user.id
}

# Check if user can delete webhook
can_delete_webhook if {
	input.user.role == "admin"
}

can_delete_webhook if {
	input.webhook.creator_id == input.user.id
}

# Check if user can test webhook
can_test_webhook if {
	can_access_webhooks
}

# ============================================================================
# Integration Rules
# ============================================================================

# Check integration access
can_access_integration if {
	input.user.role == "admin"
}

can_access_integration if {
	input.user.organization_id == input.organization.id
	input.user.org_role in ["owner", "admin"]
}

can_access_integration if {
	input.integration.creator_id == input.user.id
}

# Check if user can create integration
can_create_integration if {
	input.user.role in ["admin", "manager"]
}

can_create_integration if {
	"manage_integrations" in input.user.permissions
}

# Check if user can update integration
can_update_integration if {
	input.user.role == "admin"
}

can_update_integration if {
	input.integration.creator_id == input.user.id
}

# Check if user can delete integration
can_delete_integration if {
	input.user.role == "admin"
}

can_delete_integration if {
	input.integration.creator_id == input.user.id
}

# Check if user can authorize integration
can_authorize_integration if {
	can_create_integration
}

# ============================================================================
# Report Rules
# ============================================================================

# Check report access
can_access_reports if {
	input.user.role in ["admin", "manager"]
}

can_access_reports if {
	"view_reports" in input.user.permissions
}

can_access_reports if {
	input.report.creator_id == input.user.id
}

# Check if user can create report
can_create_report if {
	input.user.role in ["admin", "manager"]
}

can_create_report if {
	"create_reports" in input.user.permissions
}

# Check if user can export report
can_export_report if {
	can_access_reports
}

# Check if user can schedule report
can_schedule_report if {
	can_create_report
}

# Check if user can share report
can_share_report if {
	input.user.role == "admin"
}

can_share_report if {
	input.report.creator_id == input.user.id
}

# ============================================================================
# Analytics Rules
# ============================================================================

# Check analytics access
can_access_analytics if {
	input.user.role in ["admin", "manager"]
}

can_access_analytics if {
	"view_analytics" in input.user.permissions
}

# Check if user can view user analytics
can_view_user_analytics if {
	can_access_analytics
}

can_view_user_analytics if {
	input.user.id == input.target_user.id
}

# Check if user can view project analytics
can_view_project_analytics if {
	can_access_analytics
}

can_view_project_analytics if {
	can_access_project
}

# Check if user can view organization analytics
can_view_organization_analytics if {
	input.user.role == "admin"
}

can_view_organization_analytics if {
	input.user.organization_id == input.organization.id
	input.user.org_role in ["owner", "admin"]
}

# ============================================================================
# Search and Filter Rules
# ============================================================================

# Check if user can search
can_search if {
	input.user.role in ["admin", "manager", "user"]
}

# Filter search results based on access
filtered_results contains result if {
	some result in input.search_results
	can_access_resource_type(result.type, result.id)
}

# Check access to different resource types
can_access_resource_type(resource_type, resource_id) if {
	resource_type == "document"
	input.document.id == resource_id
	can_access_document
}

can_access_resource_type(resource_type, resource_id) if {
	resource_type == "project"
	input.project.id == resource_id
	can_access_project
}

can_access_resource_type(resource_type, resource_id) if {
	resource_type == "file"
	input.file.id == resource_id
	can_access_file
}

can_access_resource_type(resource_type, resource_id) if {
	resource_type == "user"
	input.target_user.id == resource_id
	can_view_user
}

# ============================================================================
# Comment and Discussion Rules
# ============================================================================

# Check if user can view comments
can_view_comments if {
	can_access_resource
}

# Check if user can create comment
can_create_comment if {
	input.user.role in ["admin", "manager", "user"]
}

can_create_comment if {
	can_access_resource
}

# Check if user can edit comment
can_edit_comment if {
	input.user.role == "admin"
}

can_edit_comment if {
	input.comment.author_id == input.user.id
}

# Check if user can delete comment
can_delete_comment if {
	input.user.role == "admin"
}

can_delete_comment if {
	input.comment.author_id == input.user.id
}

can_delete_comment if {
	can_manage_resource
	input.comment.resource_id == input.resource.id
}

# Check if user can reply to comment
can_reply_to_comment if {
	can_create_comment
}

# ============================================================================
# Tag and Label Rules
# ============================================================================

# Check if user can view tags
can_view_tags if {
	input.user.role in ["admin", "manager", "user"]
}

# Check if user can create tags
can_create_tags if {
	input.user.role in ["admin", "manager"]
}

can_create_tags if {
	"manage_tags" in input.user.permissions
}

# Check if user can update tags
can_update_tags if {
	can_create_tags
}

# Check if user can delete tags
can_delete_tags if {
	input.user.role == "admin"
}

can_delete_tags if {
	input.tag.creator_id == input.user.id
}

# Check if user can apply tags to resource
can_apply_tags if {
	can_update_resource
}

# ============================================================================
# Template Rules
# ============================================================================

# Check if user can view templates
can_view_templates if {
	input.user.role in ["admin", "manager", "user"]
}

can_view_templates if {
	input.template.public == true
}

can_view_templates if {
	input.template.creator_id == input.user.id
}

# Check if user can create template
can_create_template if {
	input.user.role in ["admin", "manager"]
}

can_create_template if {
	"create_templates" in input.user.permissions
}

# Check if user can update template
can_update_template if {
	input.user.role == "admin"
}

can_update_template if {
	input.template.creator_id == input.user.id
}

# Check if user can delete template
can_delete_template if {
	input.user.role == "admin"
}

can_delete_template if {
	input.template.creator_id == input.user.id
}

# Check if user can use template
can_use_template if {
	can_view_templates
}

# ============================================================================
# Workflow and Automation Rules
# ============================================================================

# Check if user can view workflows
can_view_workflows if {
	input.user.role in ["admin", "manager"]
}

can_view_workflows if {
	input.workflow.creator_id == input.user.id
}

can_view_workflows if {
	some participant in input.workflow.participants
	participant.user_id == input.user.id
}

# Check if user can create workflow
can_create_workflow if {
	input.user.role in ["admin", "manager"]
}

can_create_workflow if {
	"create_workflows" in input.user.permissions
}

# Check if user can update workflow
can_update_workflow if {
	input.user.role == "admin"
}

can_update_workflow if {
	input.workflow.creator_id == input.user.id
}

# Check if user can delete workflow
can_delete_workflow if {
	input.user.role == "admin"
}

can_delete_workflow if {
	input.workflow.creator_id == input.user.id
}

# Check if user can execute workflow
can_execute_workflow if {
	can_view_workflows
}

can_execute_workflow if {
	"execute_workflows" in input.user.permissions
}

# ============================================================================
# Custom Field Rules
# ============================================================================

# Check if user can view custom fields
can_view_custom_fields if {
	input.user.role in ["admin", "manager", "user"]
}

# Check if user can create custom fields
can_create_custom_fields if {
	input.user.role in ["admin", "manager"]
}

can_create_custom_fields if {
	"manage_custom_fields" in input.user.permissions
}

# Check if user can update custom fields
can_update_custom_fields if {
	can_create_custom_fields
}

# Check if user can delete custom fields
can_delete_custom_fields if {
	input.user.role == "admin"
}

can_delete_custom_fields if {
	input.custom_field.creator_id == input.user.id
}

# ============================================================================
# Import and Export Rules
# ============================================================================

# Check if user can import data
can_import_data if {
	input.user.role in ["admin", "manager"]
}

can_import_data if {
	"import_data" in input.user.permissions
}

# Check if user can export data
can_export_data if {
	input.user.role in ["admin", "manager"]
}

can_export_data if {
	"export_data" in input.user.permissions
}

# Check if user can bulk import
can_bulk_import if {
	can_import_data
	input["import"].size < input.user.import_limit
}

# Check if user can bulk export
can_bulk_export if {
	can_export_data
	input.export.size < input.user.export_limit
}

# ============================================================================
# Backup and Restore Rules
# ============================================================================

# Check if user can create backup
can_create_backup if {
	input.user.role == "admin"
}

can_create_backup if {
	input.user.organization_id == input.organization.id
	input.user.org_role == "owner"
}

# Check if user can restore from backup
can_restore_backup if {
	can_create_backup
}

# Check if user can download backup
can_download_backup if {
	can_create_backup
}

# Check if user can delete backup
can_delete_backup if {
	can_create_backup
}

# ============================================================================
# Security and Compliance Rules
# ============================================================================

# Check if user can view security settings
can_view_security_settings if {
	input.user.role == "admin"
}

can_view_security_settings if {
	input.user.organization_id == input.organization.id
	input.user.org_role in ["owner", "security_admin"]
}

# Check if user can update security settings
can_update_security_settings if {
	can_view_security_settings
}

# Check if user can view compliance reports
can_view_compliance_reports if {
	input.user.role == "admin"
}

can_view_compliance_reports if {
	input.user.organization_id == input.organization.id
	input.user.org_role in ["owner", "compliance_admin"]
}

# Check if user can generate compliance reports
can_generate_compliance_reports if {
	can_view_compliance_reports
}

# ============================================================================
# Session Management Rules
# ============================================================================

# Check if session is valid
session_valid if {
	input.session.expires_at > time.now_ns()
}

session_valid if {
	input.session.remember_me == true
	input.session.last_activity > time.now_ns() - (30 * 24 * 60 * 60 * 1000000000)
}

# Check if user can view sessions
can_view_sessions if {
	input.user.id == input.target_user.id
}

can_view_sessions if {
	input.user.role == "admin"
}

# Check if user can revoke sessions
can_revoke_session if {
	input.user.id == input.session.user_id
}

can_revoke_session if {
	input.user.role == "admin"
}

# Check if user can revoke all sessions
can_revoke_all_sessions if {
	input.user.id == input.target_user.id
}

can_revoke_all_sessions if {
	input.user.role == "admin"
}

# ============================================================================
# Two-Factor Authentication Rules
# ============================================================================

# Check if 2FA is required
two_factor_required if {
	input.organization.enforce_2fa == true
}

two_factor_required if {
	input.user.role == "admin"
}

two_factor_required if {
	input.user.high_privilege_access == true
}

# Check if user can disable 2FA
can_disable_2fa if {
	input.user.id == input.target_user.id
	not two_factor_required
}

can_disable_2fa if {
	input.user.role == "admin"
	not two_factor_required
}

# Check if user can enable 2FA
can_enable_2fa if {
	input.user.id == input.target_user.id
}

# ============================================================================
# IP Whitelist Rules
# ============================================================================

# Check if IP is allowed
ip_allowed if {
	input.organization.ip_whitelist_enabled == false
}

ip_allowed if {
	some allowed_ip in input.organization.allowed_ips
	allowed_ip == input.request.ip
}

ip_allowed if {
	some allowed_range in input.organization.allowed_ip_ranges
	ip_in_range(input.request.ip, allowed_range)
}

# Check if IP is in range
ip_in_range(ip, range) if {
	# Simplified check - would need proper CIDR implementation
	startswith(ip, range)
}

# ============================================================================
# Time-Based Access Rules
# ============================================================================

# Check if access is allowed at current time
time_based_access_allowed if {
	input.user.time_restrictions == null
}

time_based_access_allowed if {
	current_hour := time.clock([time.now_ns(), "UTC"])[0]
	current_hour >= input.user.access_start_hour
	current_hour < input.user.access_end_hour
}

time_based_access_allowed if {
	current_day := time.weekday(time.now_ns())
	current_day in input.user.allowed_days
}

# ============================================================================
# Geo-Location Rules
# ============================================================================

# Check if location is allowed
location_allowed if {
	input.organization.geo_restrictions == false
}

location_allowed if {
	some allowed_country in input.organization.allowed_countries
	allowed_country == input.request.country
}

location_allowed if {
	input.user.global_access == true
}

# ============================================================================
# Device Management Rules
# ============================================================================

# Check if device is trusted
device_trusted if {
	some device in input.user.trusted_devices
	device.id == input.request.device_id
}

device_trusted if {
	input.user.trust_all_devices == true
}

# Check if user can manage devices
can_manage_devices if {
	input.user.id == input.target_user.id
}

can_manage_devices if {
	input.user.role == "admin"
}

# Check if user can register device
can_register_device if {
	input.user.id == input.target_user.id
}

# Check if user can remove device
can_remove_device if {
	can_manage_devices
}

# ============================================================================
# Helper Functions
# ============================================================================

# Check if user has role
has_role(role) if {
	input.user.role == role
}

# Check if user has permission
has_permission(permission) if {
	some p in input.user.permissions
	p == permission
}

# Check if user is in group
in_group(group) if {
	some g in input.user.groups
	g == group
}

# Check if user is resource owner
is_owner(resource) if {
	resource.owner_id == input.user.id
}

# Check if resource is public
is_public(resource) if {
	resource.public == true
}

# Check if user is in same department
same_department(user1, user2) if {
	user1.department == user2.department
}

# Check if user is in same organization
same_organization(user1, user2) if {
	user1.organization_id == user2.organization_id
}

# Check if user is in same team
same_team(user1, user2) if {
	some team_id in user1.team_ids
	team_id in user2.team_ids
}

# Get user's effective permissions
effective_permissions contains permission if {
	some permission in input.user.permissions
}

effective_permissions contains permission if {
	some role in input.user.roles
	some permission in role.permissions
}

effective_permissions contains permission if {
	some group in input.user.groups
	some permission in group.permissions
}

# Get user's effective roles
effective_roles contains role if {
	role := input.user.role
}

effective_roles contains role if {
	some role in input.user.roles
}

# Check if resource is archived
is_archived(resource) if {
	resource.archived == true
}

is_archived(resource) if {
	resource.status == "archived"
}

# Check if resource is deleted
is_deleted(resource) if {
	resource.deleted == true
}

is_deleted(resource) if {
	resource.status == "deleted"
}

# Check if user is active
user_active if {
	input.user.status == "active"
}

user_active if {
	input.user.enabled == true
}

# Check if user is suspended
user_suspended if {
	input.user.status == "suspended"
}

# Check if user account is expired
account_expired if {
	input.user.expires_at != null
	input.user.expires_at < time.now_ns()
}

# Check if password needs reset
password_reset_required if {
	input.user.force_password_reset == true
}

password_reset_required if {
	input.user.password_changed_at != null
	input.organization.password_expiry_days != null
	input.user.password_changed_at < time.now_ns() - (input.organization.password_expiry_days * 24 * 60 * 60 * 1000000000)
}

# ============================================================================
# Resource Access Helper
# ============================================================================

can_access_resource if {
	resource_type := input.resource.type
	resource_type == "document"
	can_access_document
}

can_access_resource if {
	resource_type := input.resource.type
	resource_type == "project"
	can_access_project
}

can_access_resource if {
	resource_type := input.resource.type
	resource_type == "file"
	can_access_file
}

can_access_resource if {
	resource_type := input.resource.type
	resource_type == "folder"
	can_access_folder
}

can_manage_resource if {
	resource_type := input.resource.type
	resource_type == "document"
	can_delete_document
}

can_manage_resource if {
	resource_type := input.resource.type
	resource_type == "project"
	can_delete_project
}

can_manage_resource if {
	resource_type := input.resource.type
	resource_type == "file"
	can_delete_file
}

can_manage_resource if {
	resource_type := input.resource.type
	resource_type == "folder"
	can_delete_folder
}

can_update_resource if {
	resource_type := input.resource.type
	resource_type == "document"
	can_edit_document
}

can_update_resource if {
	resource_type := input.resource.type
	resource_type == "project"
	can_update_project
}

can_update_resource if {
	resource_type := input.resource.type
	resource_type == "file"
	can_edit_file
}

can_update_resource if {
	resource_type := input.resource.type
	resource_type == "folder"
	can_update_folder
}
