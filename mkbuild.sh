#!/bin/bash

rm -f tmp.asm
sources=$(
    for x in *.asm; do
        if [ "$x" = "elfenc.asm" ]; then
            echo "aaaelfenc "
        else
            echo "$x "
        fi
    done | sort | sed "s,aaaelfenc,elfenc.asm,;s, $,,"
)

for x in $sources; do
    basename=$(sed 's,\..*$,,' <<< "$x")
    sedstr="s,\([[:blank:]\(,]\)state,\1${basename}_state,g"
    sedstr="${sedstr};s,;org,org,"
    cat $x | sed "$sedstr"
done | col | grep -vE '@REM' > tmp.asm