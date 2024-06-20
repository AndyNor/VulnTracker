#!/bin/bash
#git update-index --chmod=+x daily_scripts.sh
#git commit -m"Executable!"

# Activate the python venv
source /var/web/venv_py311/bin/activate

# CD to project dir
cd /var/web/VulnTracker2/

# Run the scripts
python manage.py fetch_haveibeenpwned
python manage.py fetch_shodan

#python manage.py fetch_nessus
#python manage.py fetch_software
#python manage.py fetch_vulnerabilities
#python manage.py fetch_machine_vulns

