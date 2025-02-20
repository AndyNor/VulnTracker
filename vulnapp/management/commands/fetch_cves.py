from django.core.management.base import BaseCommand, CommandError
from vulnapp.models import *
from datetime import datetime, timedelta
from django.utils import timezone
import re, os, json, pytz, requests, time, random

class Command(BaseCommand):
	help = 'Fetch and store CVE data from NVD'

	#def add_arguments(self, parser):
	#	# Define a command line argument for the command
	#	parser.add_argument('-p', '--period', type=str, help='Period to fetch CVEs for (past_day, past_week, past_month)')

	def handle(self, *args, **options):
		self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
		self.headers = {
			'User-Agent': 'Oslo kommune',
			'apiKey': os.environ['NIST_CVE_APIKEY'],
		}

		scan_type = "NIST CVEs"
		scan_status = ScanStatus.objects.create(scan_type=scan_type, status='in_progress', details='{}')

		#period = options.get('period', 'past_day')

		# fetch and store vulnerabilities to database
		try:
		#	if period == 'past_day':
			cve_data = self.fetch_cves_past_3day()
		#	elif period == 'past_week':
		#		cve_data = self.fetch_cves_past_week()
		#	elif period == 'past_month':
		#		cve_data = self.fetch_cves_past_month()
		#	else:
		#		self.stdout.write(self.style.ERROR('No period specified. Using past_week'))
		#		cve_data = self.fetch_cves_past_week()

			if cve_data:
				self.save_cve_data(cve_data, scan_status)  # Corrected to pass scan_status
				scan_status.status = 'success'
				scan_status.save()
			else:
				self.stdout.write(self.style.ERROR('No CVE data fetched.'))
				scan_status.status = 'error'
				scan_status.error_message = 'No CVE data fetched.'
				scan_status.save()

		except Exception as e:
			scan_status.status = 'error'
			scan_status.error_message = str(e)
			scan_status.save()
			raise CommandError(f'An error occurred: {str(e)}')


		# Map vulnerabilities to software/keyword list based on description field in CVE data
		if cve_data:
			try:
				keyword_list = [keyword.word.lower() for keyword in Keyword.objects.all()]
				programvarelev_list = [keyword.word.lower() for keyword in ProgramvareLeverandorer.objects.all()]
				start_date = timezone.now() - timedelta(days=7)
				recent_cves = CVE.objects.filter(published_date__gte=start_date)

				def findWholeWord(word):
					return re.compile(r'\b({0})\b'.format(word), flags=re.IGNORECASE).search

				for cve in recent_cves:
					word_matches = set()
					for word in keyword_list:
						description = cve.description.replace('(','').replace(')','') # parentheses are considered word bountry by regex
						if findWholeWord(word)(description): # findWholeWord returns a method
							word_matches.add(word)

					for word in programvarelev_list:
						source_identifier = cve.source_identifier.replace('(','').replace(')','')
						if findWholeWord(word)(source_identifier): # findWholeWord returns a method
							word_matches.add(word)

					word_matches = list(word_matches)

					if len(word_matches) > 0:
						#print(f"{word_matches}: {cve.cve_id}")
						cve.keywords = json.dumps(word_matches)
						cve.save()
					else:
						cve.keywords = None
						cve.save()
				print(f"\n\nDone loading all CVE's")

			except Exception as e:
				scan_status.status = 'error'
				scan_status.error_message = "failed to map cves and keywords"
				scan_status.save()
				raise CommandError(f'An error occurred: {str(e)}')



	def fetch_cves_past_3day(self):
		today = datetime.utcnow()
		yesterday = today - timedelta(days=3)
		return self.fetch_cves(yesterday.strftime('%Y-%m-%d'), today.strftime('%Y-%m-%d'))

	def fetch_cves(self, date_start, date_end):

		retries_left = 6

		session = requests.Session()
		params = {
			'pubStartDate': f'{date_start}T00:00:00.000',
			'pubEndDate': f'{date_end}T23:59:59.000'
		}

		print(f"Connecting to {self.base_url}")
		print(f"Using parameters {params}")
		while retries_left > 0:
			try:
				response = session.get(self.base_url, headers=self.headers, params=params, timeout=(5, 200), stream=True)
				print(f"Getting {response.status_code} from service..")
				if response.status_code == 200:
					data = []
					for chunk in response.iter_content(chunk_size=8192):
						data.append(chunk)
					full_data = b''.join(data).decode('utf-8')
					return full_data  # Return raw JSON string for now
				else:
					self.stdout.write(f"Error: Received status code {response.status_code}")
					#return None
			except requests.RequestException as e:
				self.stdout.write(f"Request failed: {e}")
				#return None
			retries_left -= 1 # reduce retry counter
			if retries_left > 0:
				random_wait =  random.randint(250, 350)
				print(f"Waiting {random_wait} seconds for next attempt. {retries_left} retries left.")
				time.sleep(random_wait)

	def fetch_cves_past_week(self):
		today = datetime.utcnow()
		last_week = today - timedelta(days=7)
		return self.fetch_cves(last_week.strftime('%Y-%m-%d'), today.strftime('%Y-%m-%d'))

	def fetch_cves_past_month(self):
		today = datetime.utcnow()
		last_month = today - timedelta(days=30)
		return self.fetch_cves(last_month.strftime('%Y-%m-%d'), today.strftime('%Y-%m-%d'))


	def save_cve_data(self, cve_data, scan_status):
		try:
			data = json.loads(cve_data)

			for item in data["vulnerabilities"]:
				cve_id = item['cve']['id']
				print(f"Laster inn {cve_id}")

				description_data = item['cve']['descriptions']
				description_en = next((desc['value'] for desc in description_data if desc['lang'] == 'en'), None)
				if description_en:
					description = description_en
				else:
					description = "No description available."

				cvss_metrics = item['cve']['metrics'].get('cvssMetricV31')
				cvss_data = cvss_metrics[0]['cvssData'] if cvss_metrics else {}
				cvss_score = cvss_data.get('baseScore', 0)
				if cvss_score == 0:
					print(cvss_metrics[0])

				cvss_vector = cvss_data.get('vectorString', "N/A")
				cvss_severity = cvss_data.get('baseSeverity', 0)

				try:
					cwe_data = item['cve']['weaknesses']
					cwe = next((weakness['description'][0]['value'] for weakness in cwe_data if weakness['type'] == 'Secondary'), "N/A")
				except:
					cwe = "N/A"

				references = json.dumps(item['cve']['references'])

				published_date = datetime.strptime(item['cve']['published'], '%Y-%m-%dT%H:%M:%S.%f')
				last_modified_date = datetime.strptime(item['cve']['lastModified'], '%Y-%m-%dT%H:%M:%S.%f')

				# Make dates timezone-aware
				published_date = timezone.make_aware(published_date, timezone=pytz.UTC)
				last_modified_date = timezone.make_aware(last_modified_date, timezone=pytz.UTC)

				cve, created = CVE.objects.update_or_create(
					cve_id=cve_id,
					defaults={
						'source_identifier': item['cve']['sourceIdentifier'],
						'published_date': published_date,
						'last_modified_date': last_modified_date,
						'vuln_status': item['cve']['vulnStatus'],
						'description': description,
						'keywords': None,
						'cvss_score': cvss_score,
						'cvss_vector': cvss_vector,
						'cvss_severity': cvss_severity,
						'cwe': cwe,
						'references': references,
					}
				)

				#if created:
				#	print(f"Added {cve.cve_id}")
				#else:
				#	print(f"Updated {cve.cve_id}")

			details = scan_status.get_details()
			details['processed_cves'] = len(data["vulnerabilities"])
			scan_status.set_details(details)
			scan_status.save()

		except Exception as e:
			scan_status.status = 'error'
			scan_status.error_message = str(e)
			import traceback
			print(f"{traceback.format_exc()}")
			scan_status.save()
			self.stdout.write(self.style.ERROR(f'Failed to save CVE data: {str(e)}'))