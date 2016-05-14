#!/bin/sh

for file in $VPD_DIR/*.bin; do
        echo -e "\n$file"
        time volatility -f $file profilescan -v
done
