from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
import json
from datetime import datetime, timedelta
from vulnapp.models import Keyword, ScanStatus
from time import mktime
import requests
import os



class Command(BaseCommand):
	def handle(self, *args, **options):

		help = 'Fetch data from Kartoteket'

		scan_type = "Kartoteket"
		scan_status = ScanStatus.objects.create(scan_type=scan_type, status='in_progress', details='{}')

		try:
			url = os.environ["KARTOTEKET_SOFTWARE"]
			headers = None
			print(f"Kobler til {url}")
			connection = requests.get(url, headers=headers, timeout=1)
			print(f"Status code: {connection.status_code}")
			if connection.status_code == 200:

				Keyword.objects.all().delete()
				print(connection.text)
				data = json.loads(connection.text)
				for word in data:
					#print(word)
					Keyword.objects.get_or_create(word=word.strip())  # Assuming a list of strings

				scan_status.status = 'success'
				scan_status.save()

			else:
				scan_status.status = 'error'
				scan_status.save()
				self.stdout.write(self.style.ERROR(f'Could not connect to {url}'))


		except Exception as e:
			scan_status.status = 'error'
			scan_status.error_message = str(e)
			scan_status.save()
			self.stdout.write(self.style.ERROR(f'{str(e)}'))