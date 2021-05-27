#!/bin/bash
# Modify command in line 43


echo "### SERVER ###"
echo ""
CAP_DIR_NAME=captures
SRV_CAP_DIR_NAME=server
CAPTURE_LOC="$CAP_DIR_NAME/$SRV_CAP_DIR_NAME"

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

# echo "# Check if cs523-server is already running as docker"
# if [ "$( sudo docker container inspect -f '{{.State.Running}}' cs523-server )" == "true" ]
# then
# 	echo "Already running ==> DONE"
# else
# 	echo -n "Not running ==> Starting both dockers (cs523-server, cs523-client)... "
# 	sudo docker-compose up -d
# 	echo "==> DONE"
# fi

echo "# Force recreate cs523-server and cs523-client ..."
sudo docker-compose up -d --force-recreate
echo "==> DONE"

###### DOCKER IS RUNNING
SRV_PATH=/server

PREFIX="server-"
RND_STR=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 10 ; echo '')
EXT=".pcap"
CAP_FILE_PATH="$PREFIX$RND_STR$EXT"

# kill the server with "pkill tcpdump"
echo -n "# Starting the capture. We will end the capture in the client script... "
sudo docker exec -td cs523-server tcpdump -i any -w $SRV_PATH/$CAPTURE_LOC/$CAP_FILE_PATH
echo "==> DONE"

echo -n "# Setting up the server... "
sudo docker exec -t cs523-server python3 $SRV_PATH/server.py setup -S restaurant -S bar -S dojo
echo "==> DONE"

# kill the server with "pkill python3"
echo -n "# Starting the server in detach mode... "
sudo docker exec -td cs523-server python3 $SRV_PATH/server.py run -s $SRV_PATH/key.sec -p $SRV_PATH/key.pub
echo "==> DONE"

echo ""
echo "# INFO: Server is running and the capture is writing in $CAPTURE_LOC/$CAP_FILE_PATH on local machine"

echo "# INFO: Opening an interactive terminal on cs523-server... "
sudo docker exec -it cs523-server /bin/bash

echo ""
echo "### SERVER END ###"