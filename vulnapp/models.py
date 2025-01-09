from django.db import models
import json
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType

class Keyword(models.Model):
	# Stores programvare
	word = models.CharField(max_length=255, unique=True)

	def __str__(self):
		return self.word


class ProgramvareLeverandorer(models.Model):
	# Stores programvareleverandorer
	word = models.CharField(max_length=255, unique=True)

	def __str__(self):
		return self.word

class Blacklist(models.Model):
	# Stores blacklisted keywords
	word = models.CharField(max_length=255, unique=True)

	def __str__(self):
		return self.word

class CVE(models.Model):
	# Model to store individual CVE entries.
	cve_id = models.CharField(max_length=50, unique=True, db_index=True,)
	source_identifier = models.CharField(max_length=100)
	published_date = models.DateTimeField(db_index=True)
	last_modified_date = models.DateTimeField()
	vuln_status = models.CharField(max_length=50)
	description = models.TextField()
	keywords = models.TextField(null=True, blank=True)
	cvss_score = models.FloatField(null=True, blank=True)
	cvss_vector = models.CharField(max_length=100, null=True, blank=True)
	cvss_severity = models.CharField(max_length=50, null=True, blank=True)
	cwe = models.CharField(max_length=50, null=True, blank=True)
	references = models.TextField()
	#known_exploited = models.BooleanField(default=False)

	def __str__(self):
		return self.cve_id


	def known_exploited(self):
		#print(f"sjekker known_exploited {self.cve_id}")
		try:
			ExploitedVulnerability.objects.get(cve_id=self.cve_id)
			return True
		except:
			return False

	def keywords_list(self):
		try:
			return json.loads(self.keywords)
		except:
			return []


class Vulnerability(models.Model):
	# Model to keep track of the vulnerability overview.
	id = models.CharField(max_length=255, primary_key=True)
	name = models.CharField(max_length=255)
	description = models.TextField()
	severity = models.CharField(max_length=50)
	cvssV3 = models.FloatField(null=True, blank=True)
	cvssVector = models.CharField(max_length=255, blank=True, null=True)
	exposedMachines = models.IntegerField(default=0)
	publishedOn = models.DateField()
	updatedOn = models.DateField()
	firstDetected = models.DateField(null=True, blank=True)
	publicExploit = models.BooleanField(default=False)
	exploitVerified = models.BooleanField(default=False)
	exploitInKit = models.BooleanField(default=False)
	exploitTypes = models.JSONField(default=list)
	exploitUris = models.JSONField(default=list)
	cveSupportability = models.CharField(max_length=100)

	def __str__(self):
		return self.name



class Feed(models.Model):
	added_date = models.DateTimeField(auto_now_add=True)
	url = models.TextField(unique=True)
	title = models.TextField(null=True)
	summary = models.TextField(null=True)
	author = models.TextField(null=True)
	published = models.DateTimeField(null=True)

	def __str__(self):
		return f"Feed: {self.title}"


#['title', 'title_detail', 'summary', 'summary_detail', 'links', 'link', 'id', 'guidislink', 'published', 'published_parsed', 'authors', 'author', 'author_detail']


class MachineReference(models.Model):
	# Model to keep treack of individual vulnerabilities per host.
	vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='machine_references')
	machine_id = models.CharField(max_length=255)
	computer_dns_name = models.CharField(max_length=255, null=True, blank=True)
	os_platform = models.CharField(max_length=100, null=True, blank=True)
	rbac_group_name = models.CharField(max_length=255, null=True, blank=True)
	rbac_group_id = models.IntegerField(null=True, blank=True)
	detection_time = models.DateTimeField(null=True, blank=True)
	last_updated = models.DateTimeField(auto_now=True)

	class Meta:
		unique_together = ('vulnerability', 'machine_id')

	def __str__(self):
		return self.computer_dns_name

class HaveIBeenPwnedBreaches(models.Model):
	# Model to keep track of haveibeenpwned breaches
	name = models.CharField(max_length=100)
	title = models.CharField(max_length=100)
	domain = models.CharField(max_length=100)
	breach_date = models.DateField()
	added_date = models.DateTimeField()
	modified_date = models.DateTimeField()
	pwn_count = models.BigIntegerField()
	description = models.TextField()
	logo_path = models.URLField()
	data_classes = models.TextField()
	is_verified = models.BooleanField()
	is_fabricated = models.BooleanField()
	is_sensitive = models.BooleanField()
	is_retired = models.BooleanField()
	is_spam_list = models.BooleanField()
	is_malware = models.BooleanField()
	is_subscription_free = models.BooleanField()

	def set_data_classes(self, data):
		self.data_classes = json.dumps(data)

	def get_data_classes(self):
		return json.loads(self.data_classes)

class HaveIBeenPwnedBreachedAccounts(models.Model):
	# Model to keep track of breached accounts.
	email_address = models.CharField(max_length=150)
	breached_sites = models.TextField()
	comment = models.TextField(default=None, null=True)
	domain = models.CharField(max_length=150, null=True)


class ExploitedVulnerability(models.Model):
	# Model to keep track of exploited vulnerabilities (CISA)
	cve_id = models.CharField(max_length=20, primary_key=True)
	vendor_project = models.CharField(max_length=255)
	product = models.CharField(max_length=255)
	vulnerability_name = models.CharField(max_length=255)
	date_added = models.DateField()
	short_description = models.TextField()
	required_action = models.TextField()
	due_date = models.DateField()
	known_ransomware_campaign_use = models.CharField(max_length=255)

	def __str__(self):
		return self.cve_id

	def cve_ref(self):
		try:
			return CVE.objects.get(cve_id=self.cve_id)
		except:
			return None


class Software(models.Model):
	# Model to keep track of the software overview.
	id = models.CharField(max_length=255, primary_key=True)
	name = models.CharField(max_length=255)
	vendor = models.CharField(max_length=255)
	weaknesses = models.IntegerField()
	public_exploit = models.BooleanField()
	active_alert = models.BooleanField()
	exposed_machines = models.IntegerField()
	impact_score = models.FloatField()

	def __str__(self):
		return self.name

class SoftwareHosts(models.Model):
	# Model to keep track of the individual software entries.
	software = models.ForeignKey(Software, on_delete=models.CASCADE, related_name='software_hosts')
	host_id = models.CharField(max_length=255)  # No longer the primary key
	computer_dns_name = models.CharField(max_length=255)
	os_platform = models.CharField(max_length=255)
	rbac_group_name = models.CharField(max_length=255, blank=True, null=True)

	# If you still need to ensure that each software/host_id pair is unique, you can add this:
	class Meta:
		unique_together = ('software', 'host_id')

	def __str__(self):
		return self.computer_dns_name


class ScanStatus(models.Model):
	# Model to keep track of the status on the different scans performed.
	scan_type = models.CharField(max_length=200)
	status = models.CharField(max_length=10, choices=(('success', 'Success'), ('error', 'Error')))
	completed_at = models.DateTimeField(auto_now_add=True)
	details = models.TextField(blank=True, null=True)  # JSON string to store variable data
	error_message = models.TextField(blank=True, null=True)

	def set_details(self, data):
		"""
		Store a dictionary in the details field as a JSON string.
		"""
		if isinstance(data, dict):
			self.details = json.dumps(data)
		else:
			raise ValueError("Only dictionaries are allowed for the details field.")

	def get_details(self):
		"""
		Retrieve the details field data as a dictionary.
		"""
		if self.details:
			return json.loads(self.details)
		else:
			return {}

	def save(self, *args, **kwargs):
		"""
		Overwrite the save method to ensure details are always stored as a JSON string.
		"""
		if isinstance(self.details, dict):
			self.details = json.dumps(self.details)
		super(ScanStatus, self).save(*args, **kwargs)


class ShodanScanResult(models.Model):
	# Stores a singular shodan scan results as an individual entry.
	ip_address = models.CharField(max_length=15, unique=True)
	port = models.CharField(max_length=15, null=True)
	transport = models.CharField(max_length=15, null=True)
	product = models.CharField(max_length=300, null=True)
	vulns = models.TextField(null=True)
	http_status = models.CharField(max_length=15, null=True)
	http_title = models.CharField(max_length=300, null=True)
	http_server = models.CharField(max_length=300, null=True)
	hostnames = models.TextField(null=True)
	data = models.TextField(null=True)
	cpe23 = models.CharField(max_length=300, null=True)
	info = models.TextField(null=True)
	json_data = models.JSONField(null=True)  # Stores the JSON data returned by Shodan
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)
	comments = models.TextField(null=True)
	scan_timestamp = models.DateTimeField(null=True)
	kartoteket_result = models.TextField(null=True)



	def __str__(self):
		return self.ip_address

	def vulns_count(self):
		try:
			return len(json.loads(self.vulns))
		except:
			return ""

	def kartoteket_json(self):
		if self.kartoteket_result is not None:
			result = json.loads(self.kartoteket_result)
			if "error" in result:
				return "Ingen treff"
			else:
				dns = "".join([f"<li>{item}</li>" for item in result["dns_matches"]])
				vip = "".join([f"<li>{item}</li>" for item in result["vip_matches"]])
				vlan = "".join([f"<li>{item}</li>" for item in result["matching_vlans"][:-1]])
				pool_members = "".join([f"<li>{item['server']} {item['host_ip']} {item['external_vip']}</li>" for item in result["vip_pool_members"]])
				return f"DNS: {dns}<br>VIP: {vip}<br>VLAN: {vlan}<br>Pool members: {pool_members}"
		else:
			return "-"

	def hostnames_list(self):
		try:
			return json.loads(self.hostnames)
		except:
			return []

	def http_status_display(self):
		lookup_table = {
			100: "Continue",
			101: "Switching Protocols",
			102: "Processing",
			103: "Early Hints",
			200: "OK",
			201: "Created",
			202: "Accepted",
			203: "Non-Authoritative Information",
			204: "No Content",
			205: "Reset Content",
			206: "Partial Content",
			207: "Multi-Status",
			208: "Already Reported",
			226: "IM Used",
			300: "Multiple Choices",
			301: "Moved Permanently",
			302: "Found",
			303: "See Other",
			304: "Not Modified",
			307: "Temporary Redirect",
			308: "Permanent Redirect",
			400: "Bad Request",
			401: "Unauthorized",
			402: "Payment Required",
			403: "Forbidden",
			404: "Not Found",
			405: "Method Not Allowed",
			406: "Not Acceptable",
			407: "Proxy Authentication Required",
			408: "Request Timeout",
			409: "Conflict",
			410: "Gone",
			411: "Length Required",
			412: "Precondition Failed",
			413: "Content Too Large",
			414: "URI Too Long",
			415: "Unsupported Media Type",
			416: "Range Not Satisfiable",
			417: "Expectation Failed",
			418: "I'm a teapot",
			421: "Misdirected Request",
			422: "Unprocessable Content",
			423: "Locked",
			424: "Failed Dependency",
			425: "Too Early",
			426: "Upgrade Required",
			428: "Precondition Required",
			429: "Too Many Requests",
			431: "Request Header Fields Too Large",
			451: "Unavailable For Legal Reasons",
			500: "Internal Server Error",
			501: "Not Implemented",
			502: "Bad Gateway",
			503: "Service Unavailable",
			504: "Gateway Timeout",
			505: "HTTP Version Not Supported",
			506: "Variant Also Negotiates",
			507: "Insufficient Storage",
			508: "Loop Detected",
			510: "Not Extended",
			511: "Network Authentication Required:",
		}
		try:
			status_code = int(self.http_status) if self.http_status else 0
			return lookup_table[status_code]
		except:
			return ""

class NessusData(models.Model):
	# Model that stores the complete nessus dataset.
	data = models.TextField()
	date = models.DateTimeField(auto_now_add=True)
	scan_id = models.CharField(max_length=255)


class Comment(models.Model):
	# Model to store comments on vulnerabilities and hosts.
	content = models.TextField()
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	# Fields for generic relation
	content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
	object_id = models.CharField(max_length=255)
	content_object = GenericForeignKey('content_type', 'object_id')

	def __str__(self):
		return f"Comment on {self.content_type.model} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

class HostToBSS(models.Model):
	# Depleted model, used for importing BSS from CSV.
	host = models.CharField(max_length=255)
	bss = models.TextField()