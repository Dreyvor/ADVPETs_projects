#!/bin/bash

cell_with_problems=(3 5 7 8 11 16 21 24 25 26 30 34 35 38 39 42 45 50 51 55 59 61 64 65 67 70 71 74 75 77 79 83 86 91 92 94 97 99)
nb_http_req_wanted=(14 12 11 13 13 12 7 11 16 14 9 10 8 13 12 8 13 9 15 10 8 13 16 11 9 13 10 14 12 15 10 14 12 9 11 8 15 14)


CAP_DIR_NAME=captures
CLI_CAP_DIR_NAME=client
CAPTURE_LOC="../$CAP_DIR_NAME/$CLI_CAP_DIR_NAME"

CAP_FILE_PREFIX="client-grid_"
CAP_FILE_EXT=".pcap"

PREFIX_MERGED_FILE="merged-grid_"
MERGED_FILE_EXT=".pcap"

for idx in ${!cell_with_problems[@]}
do
	echo "##### folder ${cell_with_problems[$idx]} #####"
	path="$CAPTURE_LOC/${cell_with_problems[$idx]}"
	counter=0

	for cap_file in $(ls -tr $path/$CAP_FILE_PREFIX*)
	do
		nb_http_req=$(tshark -r $cap_file -Y 'http' -T fields -e frame.number | wc -l)
		if [ $nb_http_req -ne ${nb_http_req_wanted[$idx]} ]
		then
			# this request is NOT valid ==> delete the capture file
			rm -f $cap_file
			# sleep 0 # to fill if we comment the deletion line above
		else
			# this request is valid
			counter=$(( $counter+1 ))
		fi
	done

	echo $counter

	to_merge=( $(ls -tr $path/$CAP_FILE_PREFIX*) )
	merge_filename="$PREFIX_MERGED_FILE${cell_with_problems[$idx]}$MERGED_FILE_EXT"
	mergecap -a ${to_merge[@]} -w $path/$merge_filename

	rm -f ${to_merge[@]}

	mv $path/$merge_filename $path/$CAP_FILE_PREFIX${cell_with_problems[$idx]}$CAP_FILE_EXT
done