# SECURITY.TXT FINDER
This script uses ~6M domains (merged from Clouflare Radar, Alexa and other data sources) to identify security.txt URLs.
List is filtered firstly by 'massdns' and then by 'wfuzz'. The rest is visited to see which 

Data sources for top domains:
- Clouflare Radar (https://radar.cloudflare.com/domains)
- Cisco Umrella (http://s3-us-west-1.amazonaws.com/umbrella-static/index.html)
- Majestic Milion (https://majestic.com/reports/majestic-million)
- Tranco List (https://tranco-list.eu/list/3N7XL/1000000)

Prereqs:
- wfuzz (https://github.com/xmendez/wfuzz)
- massnd (https://github.com/blechschmidt/massdns)
