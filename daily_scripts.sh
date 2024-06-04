#!/bin/bash
#: 0 0 * * * /var/web/daily_scripts.sh

# Activate the python venv
source /var/web/py311/bin/activate

# CD to project dir
cd /var/web/VulnTracker2/

# Run the scripts
python manage.py fetch_cisa_known_exploited
python manage.py fetch_cves -p past_day
python manage.py fetch_haveibeenpwned
python manage.py fetch_nessus
python manage.py fetch_shodan
python manage.py fetch_software
#python manage.py fetch_vulnerabilities
#python manage.py fetch_machine_vulns