@echo off
cmd /k "cd /d C:\Virtualenv\VulnTracker\Scripts & activate & cd /d C:\Git\VulnTracker & python manage.py makemigrations & python manage.py migrate & pip install -r requirements.txt"
