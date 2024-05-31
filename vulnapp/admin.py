from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(Keyword)
admin.site.register(Blacklist)
admin.site.register(CVE)
admin.site.register(Vulnerability)
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
