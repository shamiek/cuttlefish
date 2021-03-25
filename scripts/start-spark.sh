if [ -z "$HADOOP_HOME" ]; then
  echo "HADOOP_HOME not set"
  exit 1
fi

if [ -z "$SPARK_HOME" ]; then
  echo "SPARK_HOME not set"
  exit 1
fi

CUTTLEFISH_HOME=/home/ubuntu/cuttlefish
if [ -z "$CUTTLEFISH_HOME" ]; then
  echo "CUTTLEFISH_HOME not set"
  exit 1
fi

CUTTLEFISH_CONFIG="$CUTTLEFISH_HOME/config"
HADOOP_CONFIG="$HADOOP_HOME/etc/hadoop"
HADOOP_CONF_DIR="$HADOOP_HOME/etc/hadoop"
MASTERFILE="$CUTTLEFISH_CONFIG/master"
SLAVESFILE="$CUTTLEFISH_CONFIG/slaves"
SPARK_CONFIG="$SPARK_HOME/conf"

# get the host name for the master node
MASTERNODE=$(head -n 1 ${MASTERFILE})

# set up the hadoop configuration file
# replaces REPLACEME in the xml files
REGEX="s/REPLACEME/${MASTERNODE}/"
sed -e $REGEX "${CUTTLEFISH_CONFIG}/core-site.xml" > "${HADOOP_CONFIG}/core-site.xml"
sed -e $REGEX "${CUTTLEFISH_CONFIG}/mapred-site.xml" > "${HADOOP_CONFIG}/mapred-site.xml"
sed -e $REGEX "${CUTTLEFISH_CONFIG}/yarn-site.xml" > "${HADOOP_CONFIG}/yarn-site.xml"
sed -e $REGEX "${CUTTLEFISH_CONFIG}/hdfs-site.xml" > "${HADOOP_CONFIG}/hdfs-site.xml"

# set up spark configuration file
cp ${CUTTLEFISH_CONFIG}/spark-defaults.conf ${SPARK_CONFIG}/spark-defaults.conf

# copy slaves file
cp ${CUTTLEFISH_CONFIG}/slaves ${SPARK_CONFIG}/slaves
cp ${CUTTLEFISH_CONFIG}/slaves ${HADOOP_CONFIG}/slaves

# For master and slaves:
# 1. kill previous hadoop processes
# 2. remove hdfs files
# 3. copy encryption (PHE) keys
#
# For slaves only:
# 1. synchronize hadoop directory with master
for node in $(cat ${MASTERFILE} ${SLAVESFILE}); do
	# trim line to get the node dns
	node="${node}" | sed -e 's/^[ \t]//'

	# skip empty lines
	if [ -z $node ]; then
		continue
	fi

    echo "At machine: $node"

	# kill previous hadoop processes that did not terminate gracefully
    for pid in $( ssh -i /home/ubuntu/cuttlefish/resources/aws_keys/microTest.pem -o "StrictHostKeyChecking no" ${node} 'pgrep -U ubuntu java' ); do
    	echo "killing pid: "$pid
		ssh -i /home/ubuntu/cuttlefish/resources/aws_keys/microTest.pem -o "StrictHostKeyChecking no" ${node} "kill -9 ${pid}"
    done

	# clear old hadoop files from datanodes
	echo "remove temp files"
	ssh -i /home/ubuntu/cuttlefish/resources/aws_keys/microTest.pem -o "StrictHostKeyChecking no" ${node} 'rm -rf /tmp/*'
	echo "remove hdfs files"
	ssh -i /home/ubuntu/cuttlefish/resources/aws_keys/microTest.pem -o "StrictHostKeyChecking no" ${node} 'rm -rf '$HOME'/hdfs/*'

    # copy encryption keys
    scp -i /home/ubuntu/cuttlefish/resources/aws_keys/microTest.pem -o "StrictHostKeyChecking no" ${CUTTLEFISH_HOME}/resources/eval_keys/* "ubuntu@${node}:/tmp/"

	# if this node is the namenode, there is nothing else to do
    if [ "$node" = "$MASTERNODE" ]; then
        continue
    fi
    if [ "$node" = "localhost" ]; then
        continue
    fi

	# sync hadoop in all datanodes
	rsync -e 'ssh -i /home/ubuntu/cuttlefish/resources/aws_keys/microTest.pem -o "StrictHostKeyChecking no"' -avz --exclude=logs "$HADOOP_HOME" ${node}:"$HOME"
	rsync -e 'ssh -i /home/ubuntu/cuttlefish/resources/aws_keys/microTest.pem -o "StrictHostKeyChecking no"' -avz "$SPARK_HOME" ${node}:"$HOME"
done

echo "Resetting hadoop"
hdfs namenode -format

echo "Starting HDFS"
start-dfs.sh
eval `ssh-agent` && ssh-add /home/ubuntu/microTest.pem && ssh-add -L
echo "Starting Spark master on this node. Starts worker on each node specified in conf/slaves"
#$SPARK_HOME/sbin/start-all.sh
