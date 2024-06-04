#!/bin/sh
echo "Opening access logs.."
sudo tail -f /etc/httpd/logs/access_log
