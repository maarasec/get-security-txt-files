#!/bin/bash

# -- SECURITY.TXT FINDER (@maara https://github.com/maarasec) ---
# This script uses ~6M domains (merged from Clouflare Radar, Alexa and other data sources) to identify security.txt URLs.
# List is filtered firstly by 'massdns' and then by 'wfuzz'. The rest is visited to see which 
# 
# Data sources for top domains:
# - Clouflare Radar (https://radar.cloudflare.com/domains)
# - Cisco Umrella (http://s3-us-west-1.amazonaws.com/umbrella-static/index.html)
# - Majestic Milion (https://majestic.com/reports/majestic-million)
# - Tranco List (https://tranco-list.eu/list/3N7XL/1000000)
# 
# Prereqs:
# - wfuzz (https://github.com/xmendez/wfuzz)
# - massnd (https://github.com/blechschmidt/massdns)

IN_FILE="in/top-domains2.txt"
OUT_FILE="out/found-security-txt.txt"
TMP_FOLDER="tmp"


# checking prereqs
if ! command -v massdns >/dev/null 2>&1; then
    echo "[!] massdns is not installed or not in the \$PATH"
fi
if ! command -v wfuzz >/dev/null 2>&1; then
    echo "[!] wfuzz is not installed or not in the \$PATH"
fi

mkdir tmp/ in/ out/ 2>/dev/null

if [ ! "$(find $TMP_FOLDER/wfuzz-in/ -mindepth 1 -maxdepth 1 | head -n 1)" ]; then
	# MASSDNS step (first filter)
	echo "[i] filtering input file with massdns tool (check whether DNS A record exists for defined URLs)"
	sleep 3
	(cd $TMP_FOLDER; wget https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt)
	massdns -r $TMP_FOLDER/resolvers.txt -t A -o S -w $TMP_FOLDER/massdns-out.txt $IN_FILE
	cat $TMP_FOLDER/massdns-out.txt | cut -d" " -f1 | sed 's/.$//' > $TMP_FOLDER/massdns-out-cleaned.txt
	# Splitting the file into chunks of 5000 lines each
	split -l 1000 $TMP_FOLDER/massdns-out-cleaned.txt $TMP_FOLDER/wfuzz-in/chunk_
fi


echo "[i] filtering input file with wfuzz tool (check whether 'URL/.well-known/security.txt' returns 200)"

sleep 3

# Loop through each chunk and test with wfuzz
for chunk in tmp/wfuzz-in/chunk_*
do
	
	# WFUZZ step (second filter)
	rm $TMP_FOLDER/wfuzz-output-cleaned.txt $TMP_FOLDER/wfuzz-output.txt 2>/dev/null
	wfuzz --req-delay 3 --conn-delay 2 -Z -X HEAD -z file,$chunk -f $TMP_FOLDER/wfuzz-output.txt https://FUZZ/.well-known/security.txt 
	cat $TMP_FOLDER/wfuzz-output.txt | grep "C=200" | cut -d'"' -f2 | uniq >  $TMP_FOLDER/wfuzz-output-cleaned.txt

	# Checking URLs (third filter)
	echo "[i] checking whether 'URL/.well-known/security.txt' returns plain text reponse which contains '@'"
	while read URL; do	
		rm $TMP_FOLDER/curl-output.txt 2>/dev/null

		# get headers and body of the response
		curl -m 5 -D $TMP_FOLDER/curl-headers.txt -o $TMP_FOLDER/curl-output.txt "https://"$URL"/.well-known/security.txt" 
		
		# paintext only are interesting for us
		if ! cat $TMP_FOLDER/curl-headers.txt | grep -i "content-type: text/plain" 1>/dev/null 2>&1 ; then
			continue
		fi

		# checking whether content length is not too small
		CONTENT_LEN=`cat $TMP_FOLDER/curl-headers.txt | grep -i "content-length:" | head -1 | cut -d" " -f2 | xargs | tr -d '[:space:]'`
		if [ "$CONTENT_LEN" -lt 5 ] ; then
			echo "[!] too short"
			continue
		fi

		# checking whether text contains email
		EMAIL_REGEX="[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
		if cat $TMP_FOLDER/curl-output.txt | grep -Eo "$EMAIL_REGEX" 1>/dev/null 2>&1; then
			echo "[+] found: https://"$URL"/.well-known/security.txt " | tee -a $OUT_FILE
			
			# checking for interesting words
			if cat $TMP_FOLDER/curl-output.txt | grep "bounty\|USD\|eligible\|hackerone\|bugcrowd\|yeswehack\|intigriti\|EUR" 1>/dev/null 2>&1; then
				echo "[+] found interesting: https://"$URL"/.well-known/security.txt " | tee -a "$OUT_FILE.priority"
			fi
		fi
	done < $TMP_FOLDER/wfuzz-output-cleaned.txt	

	mv $chunk tmp/wfuzz-done
done


# Checking URLs (third filter)
echo "[i] script finished, in total `cat $OUT_FILE | wc -l` security.txt URLs identified"
