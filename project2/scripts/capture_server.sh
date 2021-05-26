#!/bin/bash

echo "### SERVER ###"
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

echo -n "# Setting up the server... "
sudo docker exec -t cs523-server python3 $SRV_PATH/server.py setup -S restaurant -S bar -S dojo
echo "==> DONE"

# kill the server with "pkill python3"
echo -n "# Starting the server in detach mode... "
sudo docker exec -td cs523-server python3 $SRV_PATH/server.py run -s $SRV_PATH/key.sec -p $SRV_PATH/key.pub
echo "==> DONE"

# kill the server with "pkill tcpdump"
CAP_FILE_PATH=server.pcap
echo -n "# Starting the capture. We will end the capture in the client script... "
sudo docker exec -td cs523-server tcpdump -i any -w $SRV_PATH/captures/$CAP_FILE_PATH
echo "==> DONE"

echo ""
echo "# INFO: Server is running and the capture is writing in $CAP_DIR_PATH/$CAP_FILE_PATH on local machine"

echo "# INFO: Opening an interactive terminal on cs523-server... "
sudo docker exec -it cs523-server /bin/bash

echo ""
echo "### SERVER END ###"