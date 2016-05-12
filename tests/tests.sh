#!/bin/sh

for file in $VPD_DIR/*linux*.bin; do
        echo -e "\n$file"
        time volatility -f $file linux_get_profile -v
done

for file in $VPD_DIR/*.bin; do
        echo -e "\n$file"
        time volatility -f $file profilescan -v
done
