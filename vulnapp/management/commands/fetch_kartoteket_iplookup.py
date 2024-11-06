from vulnapp.models import ShodanScanResult, ScanStatus
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.db.models import Q
from time import mktime
import datetime
import requests
import json
import pytz
import os



class Command(BaseCommand):
	def handle(self, *args, **options):

		help = 'Fetch IP data from Kartoteket'

		scan_type = "Kartoteket iplookup"
		days_old = 5
		scan_status = ScanStatus.objects.create(scan_type=scan_type, status='in_progress', details='{}')
		kartoteket_iplookup_working = True # assume it's working
		utc_tz = pytz.timezone('UTC')

		try:

			tidsgrense = datetime.datetime.today() - datetime.timedelta(days=days_old)
			tidsgrense = utc_tz.localize(tidsgrense)
			for shodan_result in ShodanScanResult.objects.filter(~Q(port=None)).filter(scan_timestamp__gte=tidsgrense):

				kartoteket_result = None
				if kartoteket_iplookup_working:
					url = os.environ["KARTOTEKET_IPLOOKUP"]
					headers = {"key": os.environ["KARTOTEKET_IPLOOKUP_KEY"]}
					lookup_url = f"{url}?ip={shodan_result.ip_address}&port={shodan_result.port}"
					print(f"Kobler til {lookup_url}")
					try:
						connection = requests.get(lookup_url, headers=headers, timeout=2)
						if connection.status_code == 200:
							shodan_result.kartoteket_result = connection.text
							shodan_result.save()
							print(f"Oppdaterte {shodan_result.ip_address} sist skannet {shodan_result.scan_timestamp}")

						else:
							print(connection.status_code)
							kartoteket_iplookup_working = False
							print("Skipping Kartoteket IP-loopup")
					except Exception as e:
						self.stdout.write(self.style.ERROR(f'{str(e)}'))
						kartoteket_iplookup_working = False
				else:
					pass


			if kartoteket_iplookup_working:
				scan_status.status = 'success'
			else:
				scan_status.status = 'error'
			scan_status.save()

		except Exception as e:
			print("Scriptet feilet")
			scan_status.status = 'error'
			scan_status.error_message = str(e)
			scan_status.save()
			self.stdout.write(self.style.ERROR(f'{str(e)}'))