import os

# Django
#python manage.py shell -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
os.environ["DJANGO_SECRET_KEY"] = ""

# Authentication Entra ID

# Management commands
#fetch_cisa_known_exploited.py
#fetch_cves.py
#fetch_machine_software.py
#fetch_machine_vulns.py

#fetch_software.py
os.environ["MICROSOFT_TENANT_ID"] = ""
os.environ["MICROSOFT_CLIENT_ID"] = ""
os.environ["MICROSOFT_CLIENT_SECRET"] = ""

#fetch_vulnerabilities.py
#fetch_haveibeenpwned.py
os.environ["HAVEIBEENPWNED_API_KEY"] = ""

#fetch_nessus.py
os.environ["NESSUS_API_ACCESS_KEY"] = ""
os.environ["NESSUS_API_SECRET_KEY"] = ""

#fetch_shodan.py
os.environ["SHODAN_API_SECRET"] = ""
os.environ["SHODAN_SUBNET"] = ""