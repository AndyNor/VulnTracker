#!/bin/bash
#git update-index --chmod=+x hourly_scripts.sh
#git commit -m"Executable!"

# Activate the python venv
source /var/web/venv_py311/bin/activate

# CD to project dir
cd /var/web/VulnTracker2/

# Run the scripts
python manage.py fetch_cisa_known_exploited
python manage.py fetch_cves -p past_day

