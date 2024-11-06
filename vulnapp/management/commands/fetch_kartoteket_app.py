from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
import json
from datetime import datetime, timedelta
from vulnapp.models import *
from time import mktime
import requests
import os



class Command(BaseCommand):
	def handle(self, *args, **options):

		help = 'Fetch app data from Kartoteket'

		scan_type = "Kartoteket app"
		scan_status = ScanStatus.objects.create(scan_type=scan_type, status='in_progress', details='{}')

		#try:
		url = os.environ["KARTOTEKET_SOFTWARE"]
		headers = {"key": os.environ["KARTOTEKET_SOFTWARE_KEY"]}
		print(f"Kobler til {url}")
		connection = requests.get(url, headers=headers, timeout=1)
		print(f"Status code: {connection.status_code}")
		if connection.status_code == 200:

			for keyword in Keyword.objects.all():
				keyword.delete()
			for programvarelev in ProgramvareLeverandorer.objects.all():
				programvarelev.delete()

			#print(connection.text)
			data = json.loads(connection.text)
			print(type(data))
			for word in data["programvare"]:
				#print(word)
				Keyword.objects.create(word=word.strip())  # Assuming a list of strings

			for word in data["programvarelev"]:
				#print(word)
				ProgramvareLeverandorer.objects.create(word=word.strip())  # Assuming a list of strings

			scan_status.status = 'success'
			scan_status.save()

		else:
			print("Tilkobling feilet")
			scan_status.status = 'error'
			scan_status.save()
			self.stdout.write(self.style.ERROR(f'Could not connect to {url}'))

		"""
		except Exception as e:
			print("Scriptet feilet")
			scan_status.status = 'error'
			scan_status.error_message = str(e)
			scan_status.save()
			self.stdout.write(self.style.ERROR(f'{str(e)}'))
		"""