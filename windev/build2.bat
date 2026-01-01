@echo off
cmd /k "cd /d C:\Utvikling\kildekode\VulnTracker\.venv\Scripts & activate & cd /d C:\Utvikling\kildekode\VulnTracker & python manage.py makemigrations & python manage.py migrate & pip install -r requirements.txt"
