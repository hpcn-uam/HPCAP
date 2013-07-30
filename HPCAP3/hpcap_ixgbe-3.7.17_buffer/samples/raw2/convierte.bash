#!/bin/bash

base="/disco_capturas_0"
curr=$(pwd)
version="hpcap_ixgbe-3.7.17_buffer"

ls -rt1 $base |
	while read dir
	do
		ls -rt1 ${base}/${dir} |
			while read rawfile
			do
				pcapfile=$( echo $rawfile | awk -v FS="." '{print $1}')
				#echo "${curr}/${version}/samples/raw2/raw2pcap ${base}/${dir}/${rawfile} ${base}/${dir}/${pcapfile}"
				#${curr}/${version}/samples/raw2/raw2pcap ${base}/${dir}/${rawfile} ${base}/${dir}/${pcapfile}
				echo "${curr}/${version}/samples/raw2/raw2pcap ${base}/${dir}/${rawfile} ${base}/${dir}/${pcapfile}"
				${curr}/raw2pcap ${base}/${dir}/${rawfile} ${base}/${dir}/${pcapfile}
			done			
	done
