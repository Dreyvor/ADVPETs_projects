#!/bin/bash
# Modify commands in line 46 and 62

if [ $# -ne 1 ]
then
	echo -e "Usage:\n\t./capture_client.sh <nb_requests>"
	exit 1
fi

echo "### CLIENT ###"
echo ""
CAP_DIR_PATH=../captures

echo "# Checking if captures folder exists"
if [ -d $CAP_DIR_PATH ]
then
	echo "already exists. ==> DONE"
else
	echo -n "it does not exist ==> creating it... "
	mkdir $CAP_DIR_PATH
	echo "==> DONE"
fi

echo -n "# Check if cs523-client is already running as docker... "
if [ "$( sudo docker container inspect -f '{{.State.Running}}' cs523-client )" == "true" ]
then
	echo "Already running ==> DONE"
else
	echo "Not running ==> Please run capture_server.sh before this one... ==> ABORTED"
	echo ""
	echo "### CLIEN END ###"
	exit 1
fi

###### DOCKER IS RUNNING
CLI_PATH=/client
CAP_FILE_PATH=client.pcap
OUT_FILE_PATH=output.txt

echo -n "# Starting the capture... "
sudo docker exec -td cs523-client tcpdump -i any -w $CLI_PATH/captures/$CAP_FILE_PATH
echo "==> DONE"

echo -n "# Setting up the client... "
sudo docker exec -t cs523-client python3 $CLI_PATH/client.py get-pk
sudo docker exec -t cs523-client python3 $CLI_PATH/client.py register -u clientName -S restaurant -S bar -S dojo
echo "==> DONE"

echo "# Saving IPs in the output file... "
echo "##### CLIENT IP #####" > $CAP_DIR_PATH/$OUT_FILE_PATH
sudo docker exec -t cs523-client ip a >> $CAP_DIR_PATH/$OUT_FILE_PATH
echo "##### SERVER IP #####" >> $CAP_DIR_PATH/$OUT_FILE_PATH
sudo docker exec -t cs523-server ip a >> $CAP_DIR_PATH/$OUT_FILE_PATH
echo "==> DONE"

echo "# Running $1 random requests to server through Tor"
for (( i=1; i<=$1; i++ ))
do
	rnd=$(($RANDOM%100 + 1))
	# if ! (($i%2))
	# then
		echo "# INFO: requests $i/$1 grid $rnd"
	# fi
	echo "##### REQUEST $i/$1, GRID $rnd #####" >> $CAP_DIR_PATH/$OUT_FILE_PATH
	sudo docker exec -t cs523-client python3 $CLI_PATH/client.py grid $rnd -T restaurant -t >> $CAP_DIR_PATH/$OUT_FILE_PATH
done

# echo -n "# Waiting 30 seconds for the last request to end... "
# sleep 30
# echo "==> DONE"

echo -n "# Killing the server... "
sudo docker exec -t cs523-server pkill python3
echo "==> DONE"

echo -n "# Killing both client and server tcpdump captures... "
sudo docker exec -t cs523-client pkill tcpdump
sudo docker exec -t cs523-server pkill tcpdump
echo "==> DONE"

echo -n "# Shutting down both dockers... "
sudo docker-compose down
echo "==> DONE"

echo ""
echo "# INFO: Both dockers have been shut down!"

echo ""
echo "### CLIEN END ###"
