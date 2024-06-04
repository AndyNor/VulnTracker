#!/bin/sh
echo "Downloading latest source code.."
git fetch
git reset --hard origin/main

echo "Installing dependencies.."
pip install -q -r /var/web/VulnTracker2/requirements.txt


echo "Migrating database.."
python /var/web/VulnTracker2/manage.py makemigrations
python /var/web/VulnTracker2/manage.py migrate

echo "Collecting static files.."
python /var/web/VulnTracker2/manage.py collectstatic --noinput

echo "Restarting webserver.."
#sudo service httpd restart
sudo systemctl restart httpd.service

echo "Server is now updated!"
