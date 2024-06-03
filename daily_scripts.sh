#!/bin/bash
#: 0 0 * * * /var/web/daily_scripts.sh

# Activate the python venv
source /var/web/py311/bin/activate

# CD to project dir
cd /var/web/VulnTracker

# Run the scripts
python3 manage.py cisa_known_exploited
python3 manage.py fetch_cves -p past_day
python3 manage.py haveibeenpwned
python3 manage.py nessus_fetch
python3 manage.py shodan_scan
python3 manage.py fetch_software
python3 manage.py fetchvulnerabilities