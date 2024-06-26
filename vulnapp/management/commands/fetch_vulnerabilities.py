from django.core.management.base import BaseCommand, CommandError
from dateutil.parser import parse
import requests
from vulnapp.models import Vulnerability, ScanStatus
import project_secrets
import os
import json

# Det er ca 225.805 sårbarheter og de fleste er vi ikke berørt av. Vi henter 8000 om gangen.
# kanskje heller se på api/vulnerabilities/machinesVulnerabilities?


class Command(BaseCommand):
    help = 'Imports vulnerability data from Microsoft Security Center API'

    def parse_datetime(self, date_string):
        if date_string:
            return parse(date_string).date()
        return None

    def fetch_auth_token(self):
        url = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(os.environ["MICROSOFT_TENANT_ID"])
        payload = {
            "client_id": os.environ["MICROSOFT_CLIENT_ID"],
            "scope": "https://api.securitycenter.microsoft.com/.default",
            "client_secret": os.environ["MICROSOFT_CLIENT_SECRET"],
            "grant_type": "client_credentials"
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        response = requests.post(url, data=payload, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            return data["access_token"]
        else:
            raise CommandError('Failed to fetch authentication token.')

    def handle(self, *args, **options):
        scan_status = ScanStatus.objects.create(scan_type='Microsoft_Vulnerability_Import', status='in_progress', details='{}')
        try:
            BEARER_TOKEN = self.fetch_auth_token()
            headers = {
                'Authorization': f'Bearer {BEARER_TOKEN}',
                'Content-Type': 'application/json'
            }
            base_url = "https://api.securitycenter.microsoft.com/api/Vulnerabilities"
            page_size = 8000
            skip = 0
            processed_count = 0

            while True:
                url = f"{base_url}?$top={page_size}&$skip={skip}"
                print(f"Fetching page {url}")
                response = requests.get(url, headers=headers)

                if response.status_code == 200:
                    vulnerabilities = response.json()["value"]
                    for vuln_data in vulnerabilities:
                        processed_count += 1
        
                        published_on = self.parse_datetime(vuln_data['publishedOn'])
                        updated_on = self.parse_datetime(vuln_data['updatedOn'])
                        first_detected = self.parse_datetime(vuln_data.get('firstDetected'))

                        Vulnerability.objects.update_or_create(
                            id=vuln_data['id'],
                            defaults={
                                'name': vuln_data['name'],
                                'description': vuln_data['description'],
                                'severity': vuln_data['severity'],
                                'cvssV3': vuln_data.get('cvssV3'),
                                'cvssVector': vuln_data.get('cvssVector', ''),
                                'exposedMachines': vuln_data.get('exposedMachines', 0),
                                'publishedOn': published_on,
                                'updatedOn': updated_on,
                                'firstDetected': first_detected,
                                'publicExploit': vuln_data.get('publicExploit', False),
                                'exploitVerified': vuln_data.get('exploitVerified', False),
                                'exploitInKit': vuln_data.get('exploitInKit', False),
                                'exploitTypes': vuln_data.get('exploitTypes', []),
                                'exploitUris': vuln_data.get('exploitUris', []),
                                'cveSupportability': vuln_data.get('cveSupportability', ''),
                            }
                        )

                    if len(vulnerabilities) < page_size:
                        break  # Exit the loop if we fetched fewer items than requested
                        
                    skip += page_size  # Prepare for the next page of vulnerabilities
                else:
                    raise CommandError(f"Failed to fetch data: {response.status_code}")

            # After successfully processing, update the ScanStatus
            scan_status.status = 'success'
            scan_status.details = json.dumps({"processed_vulnerabilities": processed_count})
            scan_status.save()
            self.stdout.write(self.style.SUCCESS(f"Successfully processed {processed_count} vulnerabilities."))
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'An error occurred: {str(e)}'))
            scan_status.status = 'error'
            scan_status.error_message = str(e)
            scan_status.save()
