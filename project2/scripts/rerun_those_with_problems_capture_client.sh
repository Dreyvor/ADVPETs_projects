#!/bin/bash

cell_with_problems=(3 5 7 8 11 16 21 24 25 26 30 34 35 38 39 42 45 50 51 55 59 61 64 65 67 70 71 74 75 77 79 83 86 91 92 94 97 99)
nb_http_req_wanted=(14 12 11 13 13 12 7 11 16 14 9 10 8 13 12 8 13 9 15 10 8 13 16 11 9 13 10 14 12 15 10 14 12 9 11 8 15 14)
MAX_RETRY=40

if [ $# -ne 1 ]
then
	echo -e "Usage:\n\t./capture_client.sh <nb_requests per cell>"
	exit 1
fi

echo "### CLIENT ###"
echo ""
CAP_DIR_NAME=captures
CLI_CAP_DIR_NAME=client
CAPTURE_LOC="$CAP_DIR_NAME/$CLI_CAP_DIR_NAME"

echo "# Checking if captures folders exist... "
echo -ne "\t../$CAP_DIR_NAME "
if [ -d ../$CAP_DIR_NAME ]
then
	echo -e "already exists ==> OK"
else
	echo -ne "does not exist ==> creating it... "
	mkdir ../$CAP_DIR_NAME
	echo "==> OK"
fi

echo -ne "\t../$CAPTURE_LOC "
if [ -d ../$CAPTURE_LOC ]
then
	echo -e "already exists ==> OK"
else
	echo -ne "does not exist ==> creating it... "
	mkdir ../$CAPTURE_LOC
	echo "==> OK"
fi

# echo -n "# Check if cs523-client is already running as docker... "
# if [ "$( sudo docker container inspect -f '{{.State.Running}}' cs523-client )" == "true" ]
# then
# 	echo "Already running ==> DONE"
# else
# 	echo "Not running ==> Please run capture_server.sh before this one... ==> ABORTED"
# 	echo ""
# 	echo "### CLIEN END ###"
# 	exit 1
# fi

# ###### DOCKER IS RUNNING
CLI_PATH="/client"
CAP_FILE_PREFIX="client-grid_"
CAP_FILE_EXT=".pcap"
OUT_FILE_PREFIX="output-grid_"
OUT_FILE_EXT=".txt"
RND_STR=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 10 ; echo '')


echo -n "# Starting the capture... "
sudo docker exec -td cs523-client tcpdump -i any -w $CLI_PATH/$CAP_DIR_NAME/setup_client-$RND_STR.pcap
echo "==> DONE"

echo -n "# Setting up the client... "
sudo docker exec -t cs523-client python3 $CLI_PATH/client.py get-pk
sudo docker exec -t cs523-client python3 $CLI_PATH/client.py register -u clientName -S restaurant -S bar -S dojo
echo "==> DONE"

echo "# Saving IPs in the output file... "
echo "##### CLIENT IP #####" > ../$CAP_DIR_NAME/setup_output-$RND_STR.txt
sudo docker exec -t cs523-client ip a >> ../$CAP_DIR_NAME/setup_output-$RND_STR.txt
echo "##### SERVER IP #####" >> ../$CAP_DIR_NAME/setup_output-$RND_STR.txt
sudo docker exec -t cs523-server ip a >> ../$CAP_DIR_NAME/setup_output-$RND_STR.txt
echo "==> DONE"

echo -n "# Waiting 10 seconds for the setup to end... "
sleep 10
echo "==> DONE"

echo -n "# Killing tcpdump capture for setup... "
sudo docker exec -t cs523-client pkill tcpdump
echo "==> DONE"

echo "# Running $1 requests per cell to server through Tor"
# for (( cellID=$2; cellID<=100; cellID++ ))
for idx in ${!cell_with_problems[@]}
do
	cellID=${cell_with_problems[$idx]}
	echo "##### CELL $cellID #####"
	# Start tcpdump for the cell

	echo "# Checking if capture folder exists for this cell_id... "
	echo -ne "\t../$CAPTURE_LOC/$cellID "
	if [ -d ../$CAPTURE_LOC/$cellID ]
	then
		echo -e "already exists ==> OK"
	else
		echo -ne "does not exist ==> creating it... "
		mkdir ../$CAPTURE_LOC/$cellID
		echo "==> OK"
	fi


	counter=0
	for (( req_nb=1; req_nb<=$MAX_RETRY && counter<$1; req_nb++ ))
	do
		#echo -ne "\t# Starting tcpdump capture for this cell ... "
		sudo docker exec -td cs523-client tcpdump -i any -w $CLI_PATH/$CAPTURE_LOC/$cellID/$CAP_FILE_PREFIX$cellID-req_$req_nb$CAP_FILE_EXT
		#echo "==> writting in ../$CAPTURE_LOC/$cellID/$CAP_FILE_PREFIX$cellID$CAP_FILE_EXT ==> DONE"

		#echo -ne "\t# Resettting output file for this cell... "
		echo "" > ../$CAPTURE_LOC/$cellID/$OUT_FILE_PREFIX$cellID-req_$req_nb$OUT_FILE_EXT
		#echo "==> DONE"

		echo -ne "\t# INFO: cell $cellID, requests $req_nb/$1 with MAX_RETRY=$MAX_RETRY"
		echo "##### REQUEST $req_nb/$1, CELL $cellID #####" >> ../$CAPTURE_LOC/$cellID/$OUT_FILE_PREFIX$cellID-req_$req_nb$OUT_FILE_EXT
		sudo docker exec -t cs523-client python3 $CLI_PATH/client.py grid $cellID -T restaurant -t >> ../$CAPTURE_LOC/$cellID/$OUT_FILE_PREFIX$cellID-req_$req_nb$OUT_FILE_EXT
		
		#echo -ne "\t# Waiting 0.5 seconds for the last requests to end... "
		sleep 1
		#echo "==> DONE"

		# Kill tcpdump for the cell
		# echo -ne "\t# Killing tcpdump capture for this query... "
		sudo docker exec -t cs523-client pkill tcpdump
		# echo "==> DONE"

		# Verify enough http requests
		nb_http=$(tshark -r ../$CAPTURE_LOC/$cellID/$CAP_FILE_PREFIX$cellID-req_$req_nb$CAP_FILE_EXT -Y 'http' -T fields -e frame.number | wc -l)
		if [ $nb_http -eq ${nb_http_req_wanted[$idx]} ]
		then
			# this request is valid
			counter=$(( $counter+1 ))
		fi

		echo -e ", counter=$counter/$1"
	done

done

echo -n "# Killing the server... "
sudo docker exec -t cs523-server pkill python3
echo "==> DONE"

echo -n "# Killing server tcpdump capture... "
sudo docker exec -t cs523-server pkill tcpdump
echo "==> DONE"

echo -n "# Shutting down both dockers... "
sudo docker-compose down
echo "==> DONE"

echo ""
echo "# INFO: Both dockers have been shut down!"

echo ""
echo "### CLIEN END ###"
