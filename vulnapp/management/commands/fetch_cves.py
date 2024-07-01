from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
import requests
import json
from datetime import datetime, timedelta
import pytz
import re
from vulnapp.models import CVE, Keyword, ScanStatus, Software, Blacklist
import spacy

unique_software = []


nlp = spacy.load("en_core_web_sm")

class Command(BaseCommand):
	help = 'Fetch and store CVE data from NVD'

	def add_arguments(self, parser):
		# Define a command line argument for the command
		parser.add_argument('-p', '--period', type=str, help='Period to fetch CVEs for (past_day, past_week, past_month)')

	def handle(self, *args, **options):
		self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
		self.headers = {
			'User-Agent': 'CVEFetcher/1.0'
		}

		scan_type = "NIST CVEs"
		scan_status = ScanStatus.objects.create(scan_type=scan_type, status='in_progress', details='{}')

		period = options.get('period', 'past_day')

		try:
			if period == 'past_day':
				cve_data = self.fetch_cves_past_day()
			elif period == 'past_week':
				cve_data = self.fetch_cves_past_week()
			elif period == 'past_month':
				cve_data = self.fetch_cves_past_month()
			else:
				self.stdout.write(self.style.ERROR('Invalid period specified. Use one of: past_day, past_week, past_month'))
				return

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


	def fetch_cves_past_day(self):
		today = datetime.utcnow()
		yesterday = today - timedelta(days=1)
		return self.fetch_cves(yesterday.strftime('%Y-%m-%d'), today.strftime('%Y-%m-%d'))

	def fetch_cves(self, date_start, date_end):
		session = requests.Session()
		params = {
			'pubStartDate': f'{date_start}T00:00:00.000',
			'pubEndDate': f'{date_end}T23:59:59.000'
		}
		print(f"Using parameters {params}")

		try:
			response = session.get(self.base_url, headers=self.headers, params=params, timeout=60, stream=True)
			if response.status_code == 200:
				data = []
				for chunk in response.iter_content(chunk_size=8192):
					data.append(chunk)
				full_data = b''.join(data).decode('utf-8')
				return full_data  # Return raw JSON string for now
			else:
				self.stdout.write(f"Error: Received status code {response.status_code}")
				return None
		except requests.RequestException as e:
			self.stdout.write(f"Request failed: {e}")
			return None

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

				description_data = item['cve']['descriptions']
				description_en = next((desc['value'] for desc in description_data if desc['lang'] == 'en'), None)
				if description_en:
					description = description_en
				else:
					description = "No description available."

				cvss_metrics = item['cve']['metrics'].get('cvssMetricV31')
				cvss_data = cvss_metrics[0]['cvssData'] if cvss_metrics else {}
				cvss_score = cvss_data.get('baseScore', 0)
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


				# Match software names from description
				keyword_list = [keyword.word.lower() for keyword in Keyword.objects.all()]
				word_matches = set()

				import re
				def findWholeWord(w):
					return re.compile(r'\b({0})\b'.format(w), flags=re.IGNORECASE).search

				for word in keyword_list:
					if findWholeWord(word.lower())(description.lower()):
						word_matches.add(word)

				keywords_string = ', '.join(sorted(word_matches))


				# Process the text with spaCy
				"""
				doc = nlp(description)
				potential_software_names = set()
				for ent in doc.ents:
					if ent.label_ in ["ORG", "PRODUCT"]:
						# Normalize entity text to lowercase for case-insensitive comparison
						normalized_ent_text = ent.text.lower()
						# Check if the normalized entity text is in the keyword list
						if normalized_ent_text in keyword_list_all and normalized_ent_text not in all_blacklisted_words:
							potential_software_names.add(normalized_ent_text)
				"""


				cve, created = CVE.objects.update_or_create(
					cve_id=cve_id,
					defaults={
						'source_identifier': item['cve']['sourceIdentifier'],
						'published_date': published_date,
						'last_modified_date': last_modified_date,
						'vuln_status': item['cve']['vulnStatus'],
						'description': description,
						'keywords': keywords_string,  # Save the string of keywords
						'cvss_score': cvss_score,
						'cvss_vector': cvss_vector,
						'cvss_severity': cvss_severity,
						'cwe': cwe,
						'references': references,
					}
				)
			details = scan_status.get_details()
			details['processed_cves'] = len(data["vulnerabilities"])
			scan_status.set_details(details)
			scan_status.save()

		except Exception as e:
			scan_status.status = 'error'
			scan_status.error_message = str(e)
			scan_status.save()
			self.stdout.write(self.style.ERROR(f'Failed to save CVE data: {str(e)}'))