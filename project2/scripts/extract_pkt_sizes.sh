#!/bin/bash

CAP_PATH="../captures/captures_all_cells_20_req_each/client"
PREFIX_CAP_FILE="client-grid_"
EXT_CAP_FILE=".pcap"
NB_GRID=100

OUTPUT_FOLDER="../captures/client_extracted_sizes"
PREFIX_OUT_FILE="poi_pkt_sizes_grid_"
EXT_OUT_FILE=".txt"
PREFIX_ERR_FILE="frame_number_with_reset_grid_"
EXT_ERR_FILE=".txt"



# create the folder if it does not exists
if [ ! -d $OUTPUT_FOLDER ]
then
	mkdir $OUTPUT_FOLDER
fi

for (( cellID=1; cellID<=$NB_GRID; cellID++ ))
do
	in_file_name="$PREFIX_CAP_FILE$cellID$EXT_CAP_FILE"
	out_file_name="$PREFIX_OUT_FILE$cellID$EXT_OUT_FILE"
	tshark -r $CAP_PATH/$in_file_name -Y 'http && not json.key=="poi_list"' -T fields -e tcp.reassembled.length | sed -z 's/\n/,/g;s/,$/\n/' > $OUTPUT_FOLDER/$out_file_name

	err_file_name="$PREFIX_ERR_FILE$cellID$EXT_ERR_FILE"
	tshark -r $CAP_PATH/$in_file_name -Y 'tcp.flags.reset == 1' -T fields -e frame.number | sed -z 's/\n/,/g;s/,$/\n/' > $OUTPUT_FOLDER/$err_file_name
done
