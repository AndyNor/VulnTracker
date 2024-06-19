from django.core.management.base import BaseCommand, CommandError
from vulnapp.models import ShodanScanResult, ScanStatus
import os
import shodan
import project_secrets
import json

class Command(BaseCommand):
	help = 'Scans IP range and store the results in the database'

	def handle(self, *args, **options):

		scan_type = "Shodan"

		api_key = os.environ.get('SHODAN_API_SECRET')
		if not api_key:
			raise CommandError('SHODAN_API_SECRET environment variable not set')

		api = shodan.Shodan(api_key)

		ip_range = os.environ.get('SHODAN_SUBNET')
		if not ip_range:
			raise CommandError('SHODAN_SUBNET environment variable not set')

		scan_status = ScanStatus.objects.create(scan_type=scan_type, status='in_progress', details='{}')

		#try:
		page = 1
		processed_ips = 0
		while True:
			# Search Shodan with pagination
			results = api.search(f'net:{ip_range}', page=page)
			if not results['matches']:
				break  # Exit loop if no more results

			for result in results['matches']:
				ip_address = result['ip_str']

				ShodanScanResult.objects.update_or_create(
					ip_address=ip_address,
					defaults = {
						"port": result['port'],
						"transport": result.get('transport', None),
						"product": result.get('product', None),
						"vulns": json.dumps(list(result.get('vulns', {}).keys())),
						"http_status": result.get('http', {}).get('status', None),
						"http_title": result.get('http', {}).get('title', None),
						"http_server": result.get('http', {}).get('server', None),
						"hostnames": json.dumps(result.get('hostnames', [])),
						"data": result.get('data', []),
						"cpe23": json.dumps(result.get('cpe23', [])),
						"info": result.get('info', None),
						"json_data": result,
					}
				)
				processed_ips += 1
				self.stdout.write(self.style.SUCCESS(f'Successfully added/updated {ip_address}'))

			page += 1

		scan_status.status = 'success'
		scan_status.details = json.dumps({"processed_ips": processed_ips})
		scan_status.save()
		self.stdout.write(self.style.SUCCESS('Successfully completed the Shodan IP range scan.'))

		#except Exception as e:
		#	self.stderr.write(f'Error: {e}')
		#	scan_status.status = 'error'
		#	scan_status.error_message = str(e)
		#	scan_status.save()
		#	raise CommandError(f'Error fetching data from Shodan: {e}')