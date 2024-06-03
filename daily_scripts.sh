#!/bin/bash
#: 0 0 * * * /var/web/daily_scripts.sh

# Activate the python venv
source /var/web/py311/bin/activate

# CD to project dir
cd /var/web/VulnTracker

# Run the scripts
python3 manage.py fetch_cisa_known_exploited
python3 manage.py fetch_cves -p past_day
python3 manage.py fetch_haveibeenpwned
python3 manage.py fetch_nessus
python3 manage.py fetch_shodan
python3 manage.py fetch_software
python3 manage.py fetch_vulnerabilities
python3 manage.py fetch_machine_vulns.py