import csv
import os
import re
import requests
import json
import datetime

from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect
from django.utils import timezone
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse, NoReverseMatch
from django.views.decorators.http import require_POST
from django.contrib.contenttypes.models import ContentType
from django.shortcuts import render
from django.utils import timezone
from django.db import transaction
from django.db.models.functions import ExtractYear
from django.db.models import Count, Q, Sum

from .models import *
from .forms import *
from vulnapp.management.commands.fetch_feeds import RSS_SOURCES


def home(request):
	return render(request, 'home.html', {
		'scan_status': fetch_scan_info()
	})


def cve(request):
	"""
	Index function to display the main page.
	This page displays the CVE information from NVD as well as scan status.
	"""

	cvss_limit = 6.5
	number_days = 14
	days = []

	for day in range(number_days):
		current_datetime = timezone.now() - datetime.timedelta(days=day)
		current_date = current_datetime.date()

		day_cves = CVE.objects.filter(published_date__date=current_date)
		day_cves = day_cves.filter(cvss_score__gte=cvss_limit)
		day_cves = day_cves.exclude(keywords=None)
		day_cves = day_cves.order_by('-cvss_score')

		days.append({"datetime": current_date, "cves": list(day_cves)})

	mark_words = list(Keyword.objects.all().values_list('word', flat=True))

	return render(request, 'cve.html', {
		'days': days,
		'number_days': number_days,
		'cvss_limit': cvss_limit,
		'scan_status': fetch_scan_info(),
		'heading': "cve",
		'mark_words': mark_words,
	})


def cve_without(request):
	"""
	"""

	cvss_limit = 5.0
	number_days = 7
	days = []

	for day in range(number_days):
		current_datetime = timezone.now() - datetime.timedelta(days=day)
		current_date = current_datetime.date()

		day_cves = CVE.objects.filter(published_date__date=current_date)
		day_cves = day_cves.filter(cvss_score__gte=cvss_limit)
		day_cves = day_cves.filter(keywords=None)
		day_cves = day_cves.order_by('-cvss_score')

		days.append({"datetime": current_date, "cves": list(day_cves)})

	return render(request, 'cve.html', {
		'days': days,
		'number_days': number_days,
		'cvss_limit': cvss_limit,
		'scan_status': fetch_scan_info(),
		'heading': "cve_without",
	})


def news(request):
	"""
	This page displays the news from feeds (rss/atom).
	"""

	number_days = 7
	days = []

	sources = RSS_SOURCES

	for day in range(number_days):
		current_datetime = timezone.now() - datetime.timedelta(days=day)
		current_date = current_datetime.date()

		day_news = Feed.objects.filter(published__date=current_date)
		#day_news = day_news.exclude(keywords='')
		day_news = day_news.order_by('-published')

		days.append({"datetime": current_date, "news": list(day_news)})

	mark_words = list(Keyword.objects.all().values_list('word', flat=True))

	return render(request, 'news.html', {
		'mark_words': mark_words,
		'days': days,
		'number_days': number_days,
		'scan_status': fetch_scan_info(),
		'sources': sources,
	})


def fetch_scan_info():
	"""
	Function to fetch scan status.
	The scan status is recorded whenever a scanning script is executed, to track the status of the scan.
	"""

	unique_scan_types = ScanStatus.objects.values_list('scan_type', flat=True).distinct()

	# Then, for each type, get the most recent scan
	recent_scans = []
	for scan_type in unique_scan_types:
		recent_scan_for_type = ScanStatus.objects.filter(scan_type=scan_type).latest('completed_at')
		recent_scans.append(recent_scan_for_type)
	return recent_scans

def keyword_view(request):
	"""
	Functon to show existing keywords and add new keywords to the CVE filter.
	The user can input a single keyword or upload a CSV format.
	"""
	if request.method == 'POST':
		# Check which form is being submitted
		if 'submit_keyword' in request.POST:
			keyword_form = KeywordForm(request.POST)
			upload_form = KeywordUploadForm()  # Initialize an empty form for rendering
			if keyword_form.is_valid():
				keyword_form.save()
				return redirect('cve_keywords')
		elif 'upload_csv' in request.POST:
			keyword_form = KeywordForm()  # Initialize an empty form for rendering
			upload_form = KeywordUploadForm(request.POST, request.FILES)
			if upload_form.is_valid():
				file = request.FILES['file']
				content = json.load(file)
				print(content)
				for item in content:
					keyword, created = Keyword.objects.get_or_create(word=item.strip())  # Assuming a list of strings
				return redirect('cve_keywords')
	else:
		keyword_form = KeywordForm()
		upload_form = KeywordUploadForm()

	keywords = Keyword.objects.all()
	return render(request, 'keywords.html', {'keyword_form': keyword_form, 'upload_form': upload_form, 'keywords': keywords})

def blacklist_view(request):
	"""
	Function to add keywords to blacklist.
	Some keywords are automatically generated by the software inventory, and this might not always provide correct results, or produce false positives.
	Therefore this function is used to remove these words.
	"""

	if request.method == 'POST':
		# Check which form is being submitted
		if 'submit_blacklist' in request.POST:
			blacklist_form = BlacklistForm(request.POST)  # Re-assign with POST data if needed
			if blacklist_form.is_valid():
				blacklist_form.save()
				return redirect('blacklist')
	else:
		blacklist_form = BlacklistForm()

	blacklist_entries = Blacklist.objects.all()
	for x in blacklist_entries:
		print("X: {}".format(x))
	return render(request, 'blacklist.html', {'blacklist_form': blacklist_form, 'blacklist': blacklist_entries})

@csrf_exempt
def delete_word(request, model_name, word_id):
	"""
	The function is called whenever the user decides to delete word in the keywords or blacklist model.
	"""

	if request.method == 'DELETE':
		model = Blacklist if model_name == 'blacklist' else Keyword if model_name == 'keyword' else None
		if not model:
			return JsonResponse({'status': 'error', 'message': 'Invalid model'}, status=400)
		try:
			word = model.objects.get(pk=word_id)
			word.delete()
			return JsonResponse({'status': 'success'}, status=200)
		except model.DoesNotExist:
			return JsonResponse({'status': 'error', 'message': 'Word not found'}, status=404)
	else:
		return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

def defender_vulnerabilities(request):
	"""
	This is a helper function in order to sort out the vulnerabilities from defender before they are passed to the view function.
	The function creates statistics and does some filtering for public exploit.
	"""
	public_exploit_filter = request.GET.get('publicExploit', 'false') == 'true'
	vulnerabilities = Vulnerability.objects.filter(exposedMachines__gt=0)

	if public_exploit_filter:
		vulnerabilities = vulnerabilities.filter(publicExploit=True)

	# Calculate statistics
	vulnerabilities_stats = vulnerabilities.values('severity').annotate(total=Count('id')).order_by('severity')
	exposed_machines_stats = vulnerabilities.values('severity').annotate(exposed_total=Sum('exposedMachines')).order_by('severity')
	known_exploited_stats = vulnerabilities.filter(publicExploit=True).aggregate(
		known_exploited_count=Count('id'),
		known_exploited_exposed_machines=Sum('exposedMachines')
	)

	total_vulnerabilities = vulnerabilities.count()
	total_exposed_machines = vulnerabilities.aggregate(Sum('exposedMachines'))['exposedMachines__sum'] or 0

	# Initialize stats dictionaries
	stats_vulnerabilities = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Known_Exploited': known_exploited_stats['known_exploited_count']}
	stats_exposed_machines = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Known_Exploited': known_exploited_stats['known_exploited_exposed_machines']}

	# Fill stats for vulnerabilities
	for stat in vulnerabilities_stats:
		if stat['severity'] in stats_vulnerabilities:
			stats_vulnerabilities[stat['severity']] = stat['total']

	# Fill stats for exposed machines
	for stat in exposed_machines_stats:
		if stat['severity'] in stats_exposed_machines:
			stats_exposed_machines[stat['severity']] = stat['exposed_total']

	stats = {
		'vulnerabilities': stats_vulnerabilities,
		'exposed_machines': stats_exposed_machines,
		'Total_Vulnerabilities': total_vulnerabilities,
		'Total_Exposed_Machines': total_exposed_machines
	}

	return render(request, 'defender_vulnerabilities.html', {'vulnerabilities': vulnerabilities, 'stats': stats})

def generate_unique_comment_id(cve_id, machine_id):
	"""
	Simply generates a custom id to identify a coment
	"""
	return f"{cve_id}__{machine_id}"


def fetch_auth_token():
	"""
	Fetches the auth token in order to be able to access the Microsoft API.
	This auth token is only available for a short period of time, so this has to be called upon each request.
	"""

	url = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(os.environ["MICROSOFT_TENANT_ID"])
	payload = {
		"client_id": os.environ["MICROSOFT_CLIENT_ID"],
		"scope": "https://api.securitycenter.microsoft.com/.default",
		"client_secret": os.environ["MICROSOFT_CLIENT_SECRET"],
		"grant_type": "client_credentials"
	}
	headers = {"Content-Type": "application/x-www-form-urlencoded"}
	response = requests.post(url, data=payload, headers=headers)
	if response.status_code == 200:
		data = response.json()
		return data["access_token"]
	else:
		raise CommandError('Failed to fetch authentication token.')

def fetch_machine_references_for_cve_from_api(cve_id, token):
	"""Fetch machine references for a specific CVE ID from the API."""
	headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
	url = f"https://api.securitycenter.microsoft.com/api/vulnerabilities/{cve_id}/machineReferences"

	response = requests.get(url, headers=headers)
	if response.status_code == 200:
		return response.json()["value"]
	return None

def save_machine_references_from_api(cve, machine_data_list):
	"""Process and save machine data fetched from the API."""
	with transaction.atomic():
		for machine_data in machine_data_list:
			MachineReference.objects.create(
				vulnerability=cve,
				machine_id=machine_data['id'],
				computer_dns_name=machine_data.get('computerDnsName'),
				os_platform=machine_data.get('osPlatform'),
				rbac_group_name=machine_data.get('rbacGroupName', ''),
				rbac_group_id=machine_data.get('rbacGroupId', None),
				detection_time=parse(machine_data.get('detectionTime')) if machine_data.get('detectionTime') else None,
			)

def machine_list(request, cve_id):

	"""
	View function to show all affected hosts for a specified CVE.

	"""
	cve = get_object_or_404(Vulnerability, id=cve_id)
	machines = cve.machine_references.all()
	is_fetching_from_api = False  # Default to False

	if not machines.exists():
		token = fetch_auth_token()
		if token:
			is_fetching_from_api = True
			api_machines = fetch_machine_references_for_cve_from_api(cve_id, token)
			if api_machines:
				save_machine_references_from_api(cve, api_machines)
				machines = cve.machine_references.all()
				is_fetching_from_api = False

	machine_content_type = ContentType.objects.get_for_model(MachineReference)

	for machine in machines:
		unique_id = generate_unique_comment_id(cve_id, machine.machine_id)
		comments = Comment.objects.filter(
			content_type=machine_content_type,
			object_id=unique_id
		).order_by('-created_at')
		machine.comment_content = comments[0].content if comments.exists() else ""

		# Lookup and assign BSS value
		hostname = machine.computer_dns_name.replace(".oslofelles.oslo.kommune.no","")
		try:
			host_to_bss = HostToBSS.objects.get(host=hostname)
			machine.bss = host_to_bss.bss
		except HostToBSS.DoesNotExist:
			machine.bss = None


	# Existing filter logic for OS Platforms and RBAC Group Names
	os_platforms = machines.order_by('os_platform').values_list('os_platform', flat=True).distinct()
	rbac_group_names = machines.order_by('rbac_group_name').values_list('rbac_group_name', flat=True).distinct()
	selected_os_platform = request.GET.get('os_platform')
	if selected_os_platform:
		machines = machines.filter(os_platform=selected_os_platform)
	selected_rbac_group_name = request.GET.get('rbac_group_name')
	if selected_rbac_group_name:
		machines = machines.filter(rbac_group_name=selected_rbac_group_name)

	# New filter logic for Server/Client
	selected_machine_type = request.GET.get('machine_type')
	if selected_machine_type == 'server':
		machines = machines.filter(Q(os_platform__icontains='server') | Q(rbac_group_name__icontains='server'))
	elif selected_machine_type == 'client':
		machines = machines.exclude(Q(os_platform__icontains='server') | Q(rbac_group_name__icontains='server'))


	# Filter machines based on the selected bss, if applicable
	selected_bss = request.GET.get('bss')
	if selected_bss:
		filtered_machines = [machine for machine in machines if machine.bss == selected_bss]
		machines = filtered_machines
	else:
		filtered_machines = machines

	# Deduplicate and sort bss values for the filter dropdown
	bss_values = sorted(set(machine.bss for machine in machines if machine.bss is not None))


	context = {
		'cve': cve,
		'machines': machines,
		'os_platforms': os_platforms,
		'rbac_group_names': rbac_group_names,
		'selected_os_platform': selected_os_platform,
		'selected_rbac_group_name': selected_rbac_group_name,
		'selected_machine_type': selected_machine_type,
		'is_fetching_from_api': is_fetching_from_api,
		'bss_values': bss_values,
		'selected_bss': selected_bss,
	}
	return render(request, 'machine_list.html', context)


def fetch_vulnerabilities_for_machine_from_api(computer_dns_name, token):
	"""Fetch all CVEs associated with a specific machine from the API."""
	headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
	# The API endpoint as per Microsoft's documentation, adjust if necessary
	url = f"https://api.securitycenter.microsoft.com/api/machines/{computer_dns_name}/vulnerabilities"

	response = requests.get(url, headers=headers)
	if response.status_code == 200:
		print(response.json()["value"])
		return response.json()["value"]
	else:
		return None

def cve_list_for_machine(request, computer_dns_name):
	"""
	View function to show all vulnerabilities for a specific host.
	"""
	machine_references = MachineReference.objects.filter(computer_dns_name__icontains=computer_dns_name)
	software_list = Software.objects.filter(software_hosts__computer_dns_name__icontains=computer_dns_name).distinct()

	cves = Vulnerability.objects.filter(machine_references__in=machine_references).distinct()


	token = fetch_auth_token()
	if token:
		api_cves = fetch_vulnerabilities_for_machine_from_api(computer_dns_name, token)
		if api_cves:
			cves = Vulnerability.objects.filter(machine_references__in=machine_references).distinct()


	context = {
		'cves': cves,
		'software_list': software_list,
		'machine_id': computer_dns_name
	}
	return render(request, 'cve_list_for_machine.html', context)


# HAVEIBEENPWNED SECTION START
def haveibeenpwned_breaches(request):
	"""
	Fetches all unique breaches and shows them in a view.
	"""
	#sort_by = request.GET.get('sort', 'pwn_count_desc')
	#filter_year = request.GET.get('filter_year', None)

	# Get unique years from breach dates
	#years = HaveIBeenPwnedBreaches.objects.annotate(year=ExtractYear('breach_date')).values_list('year', flat=True).distinct().order_by('-year')

	count_recent = 40

	# Filter breaches based on the selected year
	breaches = HaveIBeenPwnedBreaches.objects.all().order_by("-added_date")[0:count_recent]
	#if filter_year:
	#	breaches = breaches.filter(breach_date__year=filter_year)

	# Adjust sorting here before adding dynamic attributes
	#if sort_by in ['pwn_count_desc', 'pwn_count_asc']:
	#	if sort_by == 'pwn_count_desc':
	#		breaches = breaches.order_by('-pwn_count')
	#	elif sort_by == 'pwn_count_asc':
	#		breaches = breaches.order_by('pwn_count')

	# Convert QuerySet to list for dynamic sorting
	breaches_list = list(breaches)

	# Add breached_users to each breach object
	for breach in breaches_list:
		breached_users = get_users_for_breach(breach)
		breach.breached_users = breached_users

		breached_users_osloskolen = get_users_for_breach_osloskolen(breach)
		breach.breached_users_osloskolen = breached_users_osloskolen
		#breach.breached_users_count = len(breached_users)  # Store count for sorting

	# Sort by breached_users_count if required
	#if sort_by in ['breached_users_desc', 'breached_users_asc']:
	#	breaches_list.sort(key=lambda x: x.breached_users_count, reverse=(sort_by == 'breached_users_desc'))

	context = {
		'breaches': breaches_list,  # Use the sorted list
		'count_recent': count_recent,
		#'current_sort': sort_by,
		#'years': years,
		#'current_filter_year': filter_year,
		'scan_status': fetch_scan_info(),
	}
	return render(request, 'haveibeenpwned.html', context)


def get_users_for_breach(breach):
	"""
	Fetches all breached users for a haveibeenpwned breach.
	Helper function for haveibeenpwned_breaches
	"""
	breached_accounts = HaveIBeenPwnedBreachedAccounts.objects.filter(breached_sites__contains=breach.name).filter(~Q(email_address__icontains="osloskolen.no"))
	users = []
	for account in breached_accounts:
		users.append(account.email_address)
	return users


def get_users_for_breach_osloskolen(breach):
	"""
	Fetches all breached users for a haveibeenpwned breach.
	Helper function for haveibeenpwned_breaches
	"""
	breached_accounts = HaveIBeenPwnedBreachedAccounts.objects.filter(breached_sites__contains=breach.name).filter(Q(email_address__icontains="osloskolen.no"))
	users = []
	for account in breached_accounts:
		users.append(account.email_address)
	return users


def get_breaches_for_user(request, email):
	"""
	Fetches all breaches that a specific user has been involved in.
	"""
	breaches = []
	search_email = email
	# Assuming the breached_sites field is a JSON-encoded list of breach names
	breached_accounts = HaveIBeenPwnedBreachedAccounts.objects.filter(email_address=search_email)
	breached_sites_names = []
	for account in breached_accounts:
		breached_sites_names.extend(json.loads(account.breached_sites))

	breaches = HaveIBeenPwnedBreaches.objects.filter(name__in=breached_sites_names).distinct()
	for breach in breaches:
		breached_users = get_users_for_breach(breach)
		breach.breached_users = breached_users

	context = {
		'breaches': breaches,
		'breached_user': search_email,
	}
	return render(request, 'haveibeenpwned.html', context)

def breached_users_list(request, breach_name):
	"""
	Fetches all breached users for a specific breach and shows them to the user in the template.
	"""

	display_filter = request.GET.get("filter", "")

	breach = get_object_or_404(HaveIBeenPwnedBreaches, name=breach_name)
	breached_accounts = HaveIBeenPwnedBreachedAccounts.objects.filter(breached_sites__contains=breach.name)

	if display_filter == "oslofelles":
		users = [account.email_address for account in breached_accounts if "osloskolen.no" not in account.email_address]
	elif display_filter == "osloskolen":
		users = [account.email_address for account in breached_accounts if "osloskolen.no" in account.email_address]
	else:
		users = [account.email_address for account in breached_accounts]

	# Map visual names to full domains
	section_map = {}
	for user in users:
		full_domain = user.split('@')[1]
		visual_name = full_domain.replace(".no", "").replace(".oslo.kommune", "")
		if len(visual_name) == 3:
			visual_name = visual_name.upper()
		else:
			visual_name = visual_name.capitalize()
		section_map[visual_name] = full_domain

	# Sort the map by visual names for consistent order in dropdown
	sorted_section_map = dict(sorted(section_map.items(), key=lambda item: item[0]))

	context = {
		'breach': breach,
		'users': users,
		'sections': sorted_section_map,  # Pass sorted map
	}
	return render(request, 'haveibeenpwned_breach.html', context)

# HAVEIBEENPWNED SECTION END

def sort_nessus_data(nessus_data):
	"""
	Sorts a list of Nessus data dictionaries by risk level.

	Parameters:
	- nessus_data: A list of dictionaries, each representing Nessus data for an entry.

	Returns:
	- A list of dictionaries sorted by the defined criticality of the 'Risk' key.
	"""
	risk_order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "None": 1}
	return sorted(nessus_data, key=lambda x: risk_order.get(x.get("Risk", "None"), 0), reverse=True)


def clean_nessus_data(nessus_data):
	""" Cleans up the nessus data so it can be properly rendered into the template """
	# Initialize a dictionary to group data by Plugin_ID
	grouped_data = {}
	for item in nessus_data:
		# Replace spaces in keys with underscores for template compatibility
		item = {key.replace(" ", "_"): value for key, value in item.items()}
		item = {key.replace(".", "_"): value for key, value in item.items()}
		plugin_id = item["Plugin_ID"]

		if plugin_id not in grouped_data:
			# Initialize entry with the current item and set affected hosts to 1
			grouped_data[plugin_id] = item
			grouped_data[plugin_id]["Affected_Hosts"] = 1
		else:
			# Increment affected hosts count for existing entries
			grouped_data[plugin_id]["Affected_Hosts"] += 1
	return grouped_data


def nessus(request):
	"""
	Fetches the latest Nessus result entry and sorts the data.
	"""
	# Fetch the newest entry
	newest_entry = NessusData.objects.order_by('-date').first()

	if newest_entry is not None:
		# Extract scan_id and date from the newest entry
		scan_id = newest_entry.scan_id
		date = newest_entry.date.strftime('%Y-%m-%d')

		# Assuming nessus_data is stored as a JSON string, parse it
		nessus_data_raw = json.loads(newest_entry.data)

		# Clean the nessus data
		grouped_data = clean_nessus_data(nessus_data_raw)

		# Assuming sort_nessus_data is a function that sorts the nessus data
		nessus_data = sort_nessus_data(list(grouped_data.values()))
	else:
		nessus_data = []  # Use an empty list if no entry is found
		scan_id = None
		date = None

	# Pass the processed nessus_data along with scan_id and date to the context
	context = {'nessus_data': nessus_data, 'scan_id': scan_id, 'date': date}
	return render(request, 'nessus.html', context)

def nessus_plugin_details(request, plugin_id):
	"""
	Fetches all vulnerable hosts for a specific vulnerability (plugin_id)
	"""
	# Fetch the newest entry with scan_id == "20"
	newest_entry = NessusData.objects.filter(scan_id="20").order_by('-date').first()

	if newest_entry is not None:
		# Assuming nessus_data is stored as a JSON string, parse it
		nessus_data_raw = json.loads(newest_entry.data)

		# Clean the nessus data
		grouped_data = clean_nessus_data(nessus_data_raw)

		# Assuming sort_nessus_data is a function that sorts the nessus data
		nessus_data = sort_nessus_data(list(grouped_data.values()))

	else:
		nessus_data = []

	context = {'nessus_data': nessus_data, 'plugin_id': plugin_id}
	return render(request, 'nessus_plugin_details.html', context)

def nessus_host_details(request, hostname):
	"""
	Fetches Nessus vulnerabilities for a hostname
	"""
	# Fetch the newest entry with scan_id == "20"
	newest_entry = NessusData.objects.filter(scan_id="20").order_by('-date').first()

	if newest_entry is not None:
		# Assuming nessus_data is stored as a JSON string, parse it
		nessus_data_raw = json.loads(newest_entry.data)

		# Clean the nessus data
		grouped_data = clean_nessus_data(nessus_data_raw)

		# Assuming sort_nessus_data is a function that sorts the nessus data
		all_data = sort_nessus_data(list(grouped_data.values()))

		# Preprocess data to replace spaces in keys with underscores
		processed_data = [{key.replace(" ", "_"): value for key, value in item.items()} for item in all_data]

		nessus_syn_info = []
		nessus_http_info = []

		# Initialize the list for other filtered data
		filtered_data = []

		for entry in processed_data:
			if entry.get('Host') == hostname:
				if entry.get('Plugin_ID') == '11219':
					nessus_syn_info.append(entry)
					continue
				if entry.get("Plugin_ID") == "19506":
					continue
				if entry.get('Plugin_ID') == "10107":
					nessus_http_info.append(entry)
				else:
					filtered_data.append(entry)
		filtered_data = sort_nessus_data(filtered_data)
	else:
		filtered_data = []

	context = {
		'nessus_data': filtered_data,
		'hostname': hostname,
		'nessus_syn_info': nessus_syn_info,
		'nessus_http_info': nessus_http_info,

	}
	return render(request, 'nessus_host_details.html', context)

def parse_nessus_scan_info(scan_text):
	"""
	Parses nessus scan info to make it a bit more digestable.
	"""
	# Define the keys in the order they appear in the scan text
	keys = [
		"Nessus version", "Nessus build", "Plugin feed version", "Scanner edition used",
		"Scanner OS", "Scanner distribution", "Scan type", "Scan name", "Scan policy used",
		"Scanner IP", "Port scanner(s)", "Port range", "Ping RTT", "Thorough tests",
		"Experimental tests", "Plugin debugging enabled", "Paranoia level", "Report verbosity",
		"Safe checks", "Optimize the test", "Credentialed checks", "Patch management checks",
		"Display superseded patches", "CGI scanning", "Web application tests",
		"Web app tests - Test mode", "Web app tests - Try all HTTP methods",
		"Web app tests - Maximum run time", "Web app tests - Stop at first flaw", "Max hosts",
		"Max checks", "Recv timeout", "Backports", "Allow post-scan editing",
		"Nessus Plugin Signature Checking", "Audit File Signature Checking", "Scan Start Date",
		"Scan duration", "Scan for malware"
	]

	# Initialize the dictionary to hold the parsed data
	parsed_data = {}

	# Process each key
	for i, key in enumerate(keys):
		start = scan_text.find(key)
		end = None  # Default end to None

		# If this is not the last key, find the start of the next key to determine the end of the current segment
		if i + 1 < len(keys):
			end = scan_text.find(keys[i + 1])

		# Extract and trim the data for the current key
		if start != -1:
			data = scan_text[start:end].replace(key, '').strip(': ').strip()
			parsed_data[key] = data

	return parsed_data


# SOFTWARE SECTION START
def software_list(request):
	"""
	Fetches and shows all software stored in the database.
	This is an overview of all software found from Microsoft Defender.
	"""
	sort_by = request.GET.get('sort', 'exposed_machines_desc')  # Default sort

	# Fetch all software entries and apply initial sorting
	software_list = Software.objects.exclude(id__contains='\n')


	# Apply sorting based on the 'sort' parameter
	if sort_by == 'exposed_machines_desc':
		software_list = software_list.order_by('-exposed_machines')
	elif sort_by == 'exposed_machines_asc':
		software_list = software_list.order_by('exposed_machines')

	# Get unique vendors for dropdown, filtering by exposed_machines > 0
	vendors = Software.objects.all().order_by('vendor').values_list('vendor', flat=True).distinct()

	# Filter by selected vendor if specified
	selected_vendor = request.GET.get('vendor')
	public_exploit_filter = request.GET.get('publicExploit', 'false') == 'true'

	if selected_vendor:
		software_list = software_list.filter(vendor=selected_vendor)
	if public_exploit_filter:
		software_list = software_list.filter(public_exploit=True)

	context = {
		'software_list': software_list,
		'vendors': vendors,
		'selected_vendor': selected_vendor,
		'current_sort': sort_by,
		'public_exploit': public_exploit_filter,

	}
	return render(request, 'software_list.html', context)


def software_list_by_software(request, software_id):
	"""
	This function shows all hosts that contain a specific software.
	"""
	# Fetch the specific Software instance
	software = get_object_or_404(Software, id=software_id)

	# Fetch related SoftwareHosts using the 'software_hosts' related name defined in the SoftwareHosts model
	hosts_query = SoftwareHosts.objects.filter(software=software)
	# Apply filters if specified
	selected_os_platform = request.GET.get('os_platform')
	selected_rbac_group_name = request.GET.get('rbac_group_name')

	if selected_os_platform:
		hosts_query = hosts_query.filter(os_platform=selected_os_platform)
	if selected_rbac_group_name:
		hosts_query = hosts_query.filter(rbac_group_name=selected_rbac_group_name)

	# Fetch unique values for filters
	os_platforms = hosts_query.order_by('os_platform').values_list('os_platform', flat=True).distinct()
	rbac_group_names = hosts_query.order_by('rbac_group_name').values_list('rbac_group_name', flat=True).distinct()

	context = {
		'software': software,
		'machines': hosts_query,
		'os_platforms': os_platforms,
		'rbac_group_names': rbac_group_names,
		'selected_os_platform': selected_os_platform,
		'selected_rbac_group_name': selected_rbac_group_name,
	}
	return render(request, 'software_list_by_software.html', context)

def all_software_hosts(request):
	"""
	Shows all software specifically on servers.
	"""
	sort_by = request.GET.get('sort', 'host_count_desc')
	selected_vendor = request.GET.get('vendor', None)

	# Identify the ContentType for SoftwareHosts
	software_content_type = ContentType.objects.get_for_model(SoftwareHosts)

	queryset = SoftwareHosts.objects.values(
		'software__name', 'software__id', 'software__vendor'
	).annotate(host_count=Count('host_id'))

	if selected_vendor:
		queryset = queryset.filter(software__vendor=selected_vendor)

	software_host_list = list(queryset)

	# Apply sorting
	if sort_by == 'host_count_desc':
		software_host_list.sort(key=lambda x: x['host_count'], reverse=True)
	elif sort_by == 'host_count_asc':
		software_host_list.sort(key=lambda x: x['host_count'], reverse=False)

	# Fetch comments for each software
	for software in software_host_list:
		comments = Comment.objects.filter(
			content_type=software_content_type,
			object_id=software['software__id']
		)
		software['comment'] = comments[0].content if comments.exists() else ""
		try:
			software['url'] = reverse('host_list_by_software', kwargs={'software_id': software['software__id']})
		except NoReverseMatch:
			software['url'] = None

	vendors = {entry['software__vendor'] for entry in software_host_list}

	context = {
		'software_list': software_host_list,
		'current_sort': sort_by,
		'vendors': sorted(vendors),
		'selected_vendor': selected_vendor,
	}
	return render(request, 'software_list_server.html', context)


# SOFTWARE SECTION END


def shodan_stale(request):
	"""
	Shows all of the stale results from Shodan, with filters and sorting to structure the data.
	"""
	recent_days = 14
	tidsgrense = datetime.date.today() - datetime.timedelta(days=recent_days)
	results = ShodanScanResult.objects.all().filter(~Q(port=None)).filter(Q(updated_at__lt=tidsgrense) | Q(scan_timestamp__lt=tidsgrense)).order_by('-created_at')

	shodan_content_type = ContentType.objects.get_for_model(ShodanScanResult)
	for result in results:
		data = result.json_data
		if data == None:
			continue
		# Attempt to fetch the comment for this result
		comments = Comment.objects.filter(
			content_type=shodan_content_type,
			object_id=result.id
		)
		comment_content = comments[0].content if comments else ""  # Use the first comment's content if exists
		result.comment_content = comment_content

	stats = {
		'total_ips': results.count(),
	}

	context = {
		'recent_days': recent_days,
		'stale': True,
		'results': results,
		'stats': stats,
		'scan_status': fetch_scan_info(),
	}

	return render(request, 'shodan_results.html', context)


def shodan(request):
	"""
	Shows all of the results from Shodan, with filters and sorting to structure the data.
	"""
	recent_days = 14
	tidsgrense = datetime.date.today() - datetime.timedelta(days=recent_days)
	results = ShodanScanResult.objects.all().filter(~Q(port=None)).filter(Q(updated_at__gte=tidsgrense) & Q(scan_timestamp__gte=tidsgrense)).order_by('-created_at')

	shodan_content_type = ContentType.objects.get_for_model(ShodanScanResult)
	for result in results:
		data = result.json_data
		if data == None:
			continue
		# Attempt to fetch the comment for this result
		comments = Comment.objects.filter(
			content_type=shodan_content_type,
			object_id=result.id
		)
		comment_content = comments[0].content if comments else ""  # Use the first comment's content if exists
		result.comment_content = comment_content

	stats = {
		'total_ips': results.count(),
	}

	context = {
		'recent_days': recent_days,
		'stale': False,
		'results': results,
		'stats': stats,
		'scan_status': fetch_scan_info(),
	}

	return render(request, 'shodan_results.html', context)


@require_POST
def add_comment(request):
	"""
	Function to add a comment on the different fields around the application.
	"""
	object_id = request.POST.get('result_id')
	comment_content = request.POST.get('comment_content')
	comment_type = request.POST.get('comment_type')

	# Handle comments for software entities
	if comment_type == 'software':
		content_type = ContentType.objects.get_for_model(SoftwareHosts)
	elif comment_type == 'cve-machine':
		# Handle comments for CVE-Machine combinations
		content_type = ContentType.objects.get_for_model(MachineReference)
	elif comment_type == 'shodan':
		content_type = ContentType.objects.get_for_model(ShodanScanResult)
	else:
		# Log or handle unsupported comment types
		print(f"Unsupported comment type: {comment_type}")
		return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

	# Create or update the comment with the correct content type and object ID
	comment, created = Comment.objects.update_or_create(
		content_type=content_type,
		object_id=object_id,
		defaults={'content': comment_content}
	)

	print(f"Comment {'created' if created else 'updated'}: {comment}")
	return HttpResponseRedirect(request.META.get('HTTP_REFERER'))


def push_pushover(message):
	import os, requests
	import http.client
	USER_KEY = os.environ['PUSHOVER_USER_KEY']
	APP_TOKEN = os.environ['PUSHOVER_APP_TOKEN']
	CONTEXT = os.environ['PUSHOVER_CONTEXT']
	if USER_KEY != "" and APP_TOKEN != "":
		try:
			payload = {"message": f"{CONTEXT}: {message}", "user": USER_KEY, "token": APP_TOKEN}
			r = requests.post('https://api.pushover.net/1/messages.json', data=payload, headers={'User-Agent': 'Python'})
			conn = http.client.HTTPSConnection("api.pushover.net:443")
			print(f"Varsel sendt via PushOver")
		except Exception as e:
			print(f"Error: Kan ikke sende til pushover grunnet {e}")
		return
	print(f"Pushover er ikke konfigurert")