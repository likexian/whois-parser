#!/bin/bash
set -u
find examples/ -mmin +60 -type f ! -regex ".*\.[po][ru][te]$" -print0  | while IFS= read -r -d '' path; do
	# removed, not permitted, other
	# google.google, bin.hm, google.hm, ats.aq, com, google.ch, cn, yp.mo, 
	# moo.mo, google.tk, job.ybs, switch.ch, asf.aq
	f=$(basename $path)
	ext=$(echo $path | sed -r "s/.+\.(.+)$/\1/")
	dom=$(echo $f | sed -r "s/${ext}_//")
	printf 'checking %s\n' "$dom"
	whois $dom > $path
    printf 'updated %s\n' "$dom"
done
