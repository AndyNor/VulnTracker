from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(Keyword)
admin.site.register(Blacklist)
admin.site.register(CVE)

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
	list_display = ('id', 'name', 'severity', 'cvssV3', 'cvssVector', 'exposedMachines', 'publishedOn', 'updatedOn', 'firstDetected', 'publicExploit', 'exploitVerified', 'cveSupportability')
	search_fields = ('name', 'description', 'id',)
	list_filter = ('severity', 'cvssV3', 'exposedMachines')


admin.site.register(MachineReference)
admin.site.register(HaveIBeenPwnedBreaches)
admin.site.register(HaveIBeenPwnedBreachedAccounts)
admin.site.register(ExploitedVulnerability)
admin.site.register(Software)
admin.site.register(SoftwareHosts)
admin.site.register(ScanStatus)
admin.site.register(ShodanScanResult)
admin.site.register(NessusData)
admin.site.register(Comment)
admin.site.register(HostToBSS)
