#!/bin/bash

FILE="encrypted"

for i in {a..z}; do
	echo "$i = $(fgrep -o $i $FILE | wc -l)"
done

echo ". = $(fgrep -o '.' $FILE | wc -l)"
echo "  = $(fgrep -o ' ' $FILE | wc -l)"

