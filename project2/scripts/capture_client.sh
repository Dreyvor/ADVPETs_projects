#!/bin/bash

if [ $# -ne 2 ]
then
	echo -e "Usage:\n\t./capture_client.sh <nb_requests per cell> <start from cell nb [1-100]>"
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

echo "# Starting from cell number $2"

echo "# Running $1 requests per cell to server through Tor"
for (( cellID=$2; cellID<=100; cellID++ ))
do
	echo "##### CELL $cellID #####"
	# Start tcpdump for the cell
	echo -ne "\t# Starting tcpdump capture for this cell... "
	sudo docker exec -td cs523-client tcpdump -i any -w $CLI_PATH/$CAPTURE_LOC/$CAP_FILE_PREFIX$cellID$CAP_FILE_EXT
	echo "==> writting in ../$CAPTURE_LOC/$CAP_FILE_PREFIX$cellID$CAP_FILE_EXT ==> DONE"

	echo -ne "\t# Resettting output file for this cell... "
	echo "" > ../$CAPTURE_LOC/$OUT_FILE_PREFIX$cellID$OUT_FILE_EXT
	echo "==> DONE"

	for (( req_nb=1; req_nb<=$1; req_nb++ ))
	do
		echo -e "\t# INFO: cell $cellID, requests $req_nb/$1"
		echo "##### REQUEST $req_nb/$1, CELL $cellID #####" >> ../$CAPTURE_LOC/$OUT_FILE_PREFIX$cellID$OUT_FILE_EXT
		sudo docker exec -t cs523-client python3 $CLI_PATH/client.py grid $cellID -T restaurant -t >> ../$CAPTURE_LOC/$OUT_FILE_PREFIX$cellID$OUT_FILE_EXT
	done

	echo -ne "\t# Waiting 2 seconds for the last requests to end... "
	sleep 2
	echo "==> DONE"

	# Kill tcpdump for the cell
	echo -ne "\t# Killing tcpdump capture for this cell... "
	sudo docker exec -t cs523-client pkill tcpdump
	echo "==> DONE"
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
