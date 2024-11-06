from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
import json
from datetime import datetime, timedelta
from vulnapp.models import ScanStatus, ExploitedVulnerability
from time import mktime
from django.core import serializers
import requests
import os



class Command(BaseCommand):
	def handle(self, *args, **options):

		help = 'Send CVEs known exploited to Kartoteket'

		scan_type = "Kartoteket exploited"
		scan_status = ScanStatus.objects.create(scan_type=scan_type, status='in_progress', details='{}')

		try:
			url = os.environ["KARTOTEKET_KNOWNEXP"]
			headers = {"key": os.environ["KARTOTEKET_KNOWNEXP_KEY"]}
			print(f"Kobler til {url}")

			number_of_cve = ExploitedVulnerability.objects.all().count()
			print(f"Sending {number_of_cve} known exploted CVEs..")
			json_data = serializers.serialize('json', ExploitedVulnerability.objects.all())

			connection = requests.post(url, headers=headers, json=json_data, timeout=60)
			print(f"Status code: {connection.status_code}")
			print(f"Data: {connection.text}")
			if connection.status_code == 200:

				scan_status.status = 'success'
				scan_status.save()

			else:
				print("Tilkobling feilet")
				scan_status.status = 'error'
				scan_status.save()
				self.stdout.write(self.style.ERROR(f'Could not connect to {url}'))

		except Exception as e:
			print("Scriptet feilet")
			scan_status.status = 'error'
			scan_status.error_message = str(e)
			scan_status.save()
			self.stdout.write(self.style.ERROR(f'{str(e)}'))
