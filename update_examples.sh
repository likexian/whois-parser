#!/bin/bash
set -u

# removed, not permited, other
skiplist="bin.hm google.hm ats.aq google.ch yp.mo moo.mo google.tk job.ybs switch.ch asf.aq"

find examples/ -mmin +1 -type f ! -regex ".*\.[po][ru][te]$" -print0  | while IFS= read -r -d '' path; do
	f=$(basename $path)
	ext=$(echo $path | sed -r "s/.+\.(.+)$/\1/")
	dom=$(echo $f | sed -r "s/${ext}_//" || echo $f | sed -r "s/(.+)_.+$/\1/")

	# skiplist
	if [[ $skiplist =~ (^|[[:space:]])$dom($|[[:space:]]) ]]; then
		printf 'skipping %s\n' "$dom"
		continue
	fi

	# check if root
	# if [[ $rootlist =~ (^|[[:space:]])$f($|[[:space:]]) ]]; then
		# dom=$(echo $f | sed -r "s/(.+)_.+$/\1/")
	# fi

	whois $dom > $path
	printf 'updated %s (%s)\n' "$dom" "$path"
done
