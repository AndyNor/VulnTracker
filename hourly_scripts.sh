#!/bin/bash
# 0 7,11,14,17 * * * /var/web/hourly_scripts.sh

# Activate the python venv
source /var/web/venv_py311/bin/activate

# CD to project dir
cd /var/web/VulnTracker2/

# Run the scripts
python manage.py fetch_cisa_known_exploited
python manage.py fetch_cves -p past_day