from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(Keyword)
admin.site.register(Blacklist)
admin.site.register(MachineReference)
admin.site.register(ExploitedVulnerability)
admin.site.register(Software)
admin.site.register(SoftwareHosts)
admin.site.register(NessusData)
admin.site.register(HostToBSS)

@admin.register(CVE)
class CVEAdmin(admin.ModelAdmin):
	list_display = ('cve_id', 'cvss_score', 'source_identifier', 'vuln_status', 'keywords')
	search_fields = ('cve_id', 'description', 'source_identifier',)


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
	list_display = ('id', 'description', 'severity', 'cvssV3', 'exploitTypes', 'exposedMachines', 'publishedOn', 'updatedOn', 'publicExploit', 'exploitVerified')
	search_fields = ('name', 'description', 'id', 'cvssVector', 'exploitUris')
	list_filter = ('severity', 'publicExploit', 'updatedOn', 'exploitInKit',)


@admin.register(HaveIBeenPwnedBreaches)
class HaveIBeenPwnedBreachesAdmin(admin.ModelAdmin):
	list_display = ('name', 'title', 'domain', 'pwn_count', 'breach_date', 'added_date', 'modified_date')
	search_fields = ('name', 'title',)


@admin.register(HaveIBeenPwnedBreachedAccounts)
class HHaveIBeenPwnedBreachedAccountsAdmin(admin.ModelAdmin):
	list_display = ('email_address', 'breached_sites', 'domain', 'comment',)
	search_fields = ('email_address', 'breached_sites', 'domain',)
	list_filter = ('comment',)


@admin.register(Feed)
class FeedAdmin(admin.ModelAdmin):
	list_display = ('url', 'title', 'author', 'published')
	search_fields = ('title', 'summary',)
	list_filter = ('author',)


@admin.register(ScanStatus)
class ScanStatusAdmin(admin.ModelAdmin):
	list_display = ('completed_at', 'scan_type', 'status', 'error_message')
	list_filter = ('scan_type',)


@admin.register(ShodanScanResult)
class ShodanScanResultAdmin(admin.ModelAdmin):
	list_display = ('ip_address', 'created_at', 'updated_at', 'transport', 'port', 'product', 'info', 'http_status', 'http_server', 'http_title', 'hostnames', 'cpe23', 'kartoteket_result')
	search_fields = ('ip_address', 'transport', 'port', 'product', 'vulns', 'http_status', 'http_title', 'http_server', 'hostnames', 'data', 'cpe23', 'info')


@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
	list_display = ('object_id', 'created_at', 'updated_at', 'content',)


