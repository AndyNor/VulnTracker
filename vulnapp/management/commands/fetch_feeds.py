from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
import json
from datetime import datetime, timedelta
import pytz
import re
from vulnapp.models import Keyword, ScanStatus, Feed
import feedparser
from time import mktime
import pytz



class Command(BaseCommand):
	def handle(self, *args, **options):

		help = 'Fetch and store RSS feeds'

		scan_type = "RSS feeds"
		scan_status = ScanStatus.objects.create(scan_type=scan_type, status='in_progress', details='{}')

		try:

			rss_sources = [
				"https://feeds.feedburner.com/TheHackersNews",
				"https://www.securityweek.com/feed/",
				"https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
				"https://www.digi.no/rss",
				"https://www.bleepingcomputer.com/feed/",
				#"https://telenorsoc-news.blogspot.com/feeds/posts/default",
			]

			for rss_source in rss_sources:
				try:
					feed = feedparser.parse(rss_source)
					if feed.status == 200:
						for entry in feed.entries:

							published = timezone.make_aware(datetime.fromtimestamp(mktime(entry.published_parsed)), timezone=pytz.UTC)
							author = entry.author_detail.name if hasattr(entry, "author_detail") else None

							e, created = Feed.objects.update_or_create(
								url=entry.id,
								defaults={
									'title': entry.title,
									'summary': entry.summary,
									'author': author,
									'published': published,
								}
							)
					print(f"Successfully read {rss_source}")
				except:
					print(f"Failed to read {rss_source}")


			scan_status.status = 'success'
			scan_status.save()


		except Exception as e:
			scan_status.status = 'error'
			scan_status.error_message = str(e)
			scan_status.save()
			self.stdout.write(self.style.ERROR(f'Failed to read RSS: {str(e)}'))