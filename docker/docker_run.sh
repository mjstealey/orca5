#!/bin/bash

ORCA_CONFIG_DIR="/opt/orca" # JRE Vendor will be appended later, e.g. -oracle

DOCKER_NAME_MYSQL="orca-mysql"
DOCKER_NAME_AM_BROKER="orca-am-broker"
DOCKER_NAME_SM="orca-sm"
DOCKER_NAME_CONTROLLER="orca-controller"

DOCKER_NET_NAME="orca"
DOCKER_ORCA_IMAGE_TAG="oracle_1.8"

while [[ $# -gt 1 ]]
do
key="$1"

case $key in
    -t|--tag-name)
    DOCKER_ORCA_IMAGE_TAG="$2"
    shift # past argument
    ;;
    *)
            # unknown option
    ;;
esac
shift # past argument or value
done

# get JRE Vendor from tag name
# https://stackoverflow.com/a/15988793/2955846
# ${var##*SubStr} # will drop begin of string upto last occur of `SubStr`
# JRE Vendor is always after a '-' in tag
DOCKER_JRE_VENDOR=${DOCKER_ORCA_IMAGE_TAG##*-}
ORCA_CONFIG_DIR=${ORCA_CONFIG_DIR}-${DOCKER_JRE_VENDOR}

# remove stopped or running containers
f_rm_f_docker_container ()
{
  #container_name="$1"
  RUNNING=$(docker inspect --format="{{ .State.Running }}" $1 2> /dev/null)

  # if it's not there at all, we don't need to remove it
  if [ $? -ne 1 ]; then
    echo -n "Removing container: "
    docker rm -f $1

    # check exit status, and kill script if not successful
    if [ $? -ne 0 ]
    then
      exit $?
    fi
  fi
}

# Remove any previous docker containers of name
echo "Info: removing any previous Orca containers..."
f_rm_f_docker_container ${DOCKER_NAME_CONTROLLER}
f_rm_f_docker_container ${DOCKER_NAME_SM}
f_rm_f_docker_container ${DOCKER_NAME_AM_BROKER}

# Create docker network
NET_INSPECT=$(docker network inspect ${DOCKER_NET_NAME} 2> /dev/null)
# only create it if it doesn't already exist
if [ $? -eq 1 ]; then
  echo -n "Creating docker network ${DOCKER_NET_NAME}: "
  docker network create ${DOCKER_NET_NAME}
else
  echo "Info: Docker network '${DOCKER_NET_NAME}' already exists."
fi

# Docker-on-Mac is a bit slower
var_sleep=15
if [[ $OSTYPE == darwin* ]]
then
  let "var_sleep *= 15"
fi

# The MySQL container probably doesn't need to be restarted
RUNNING=$(docker inspect --format="{{ .State.Running }}" $DOCKER_NAME_MYSQL 2> /dev/null)

if [ $? -eq 1 ] || [ "$RUNNING" == "false" ]; then
  if [ "$RUNNING" == "false" ]; then
    f_rm_f_docker_container ${DOCKER_NAME_MYSQL}
  fi

  # Start Orca MySQL server
  echo -n "docker run ${DOCKER_NAME_MYSQL}: "
  docker run -d \
             --net ${DOCKER_NET_NAME} \
             --name ${DOCKER_NAME_MYSQL} \
             --hostname orca-mysql \
             --publish 127.0.0.1:3306:3306\
             renci/orca-mysql

  # check exit status from docker run, and kill script if not successful
  if [ $? -ne 0 ]
  then
    exit $?
  fi

  # Sleep
  echo -n "Sleeping for ${var_sleep} to allow ${DOCKER_NAME_MYSQL} container to start ..."
  sleep ${var_sleep};
  echo " done."
else
  echo "Container '${DOCKER_NAME_MYSQL}' is running; not restarting."
fi

# Start Orca AM+Broker
echo -n "docker run ${DOCKER_NAME_AM_BROKER}:${DOCKER_ORCA_IMAGE_TAG} "
docker run -d \
           --net ${DOCKER_NET_NAME} \
           --name ${DOCKER_NAME_AM_BROKER} \
           --hostname orca-am-broker \
           --publish 127.0.0.1:12080:12080\
           --publish 127.0.0.1:9010:9010 \
           --volume ${ORCA_CONFIG_DIR}/am+broker/config:/etc/orca/am+broker-12080/config \
           --volume ${ORCA_CONFIG_DIR}/am+broker/ndl:/etc/orca/am+broker-12080/ndl \
           renci/orca-am-broker:${DOCKER_ORCA_IMAGE_TAG} \
           debug # DEBUG mode, for JMX remote monitoring

# check exit status from docker run, and kill script if not successful
if [ $? -ne 0 ]
then
  exit $?
fi

# Sleep
echo -n "Sleeping for ${var_sleep} to allow ${DOCKER_NAME_AM_BROKER} container to start ..."
sleep ${var_sleep};
echo " done."

# Start Orca SM
echo -n "docker run ${DOCKER_NAME_SM}:${DOCKER_ORCA_IMAGE_TAG} "
docker run -d \
           --net ${DOCKER_NET_NAME} \
           --name ${DOCKER_NAME_SM} \
           --hostname orca-sm \
           --publish 127.0.0.1:14080:14080\
           --publish 127.0.0.1:9011:9010 \
           --volume ${ORCA_CONFIG_DIR}/sm/config:/etc/orca/sm-14080/config \
           renci/orca-sm:${DOCKER_ORCA_IMAGE_TAG} \
           debug # DEBUG mode, for JMX remote monitoring

# check exit status from docker run, and kill script if not successful
if [ $? -ne 0 ]
then
  exit $?
fi

# Sleep
let "var_sleep /= 2";
echo -n "Sleeping for ${var_sleep} to allow ${DOCKER_NAME_SM} container to start ..."
sleep ${var_sleep};
echo " done."

# Start Orca Controller
echo -n "docker run ${DOCKER_NAME_CONTROLLER}:${DOCKER_ORCA_IMAGE_TAG} "
docker run -d \
           --net ${DOCKER_NET_NAME} \
           --name ${DOCKER_NAME_CONTROLLER} \
           --hostname orca-controller \
           --publish 127.0.0.1:11443:11443 \
           --publish 127.0.0.1:9012:9010 \
           --volume ${ORCA_CONFIG_DIR}/controller/config:/etc/orca/controller-11080/config \
           renci/orca-controller:${DOCKER_ORCA_IMAGE_TAG} \
           debug # DEBUG mode, for JMX remote monitoring

# check exit status from docker run, and kill script if not successful
if [ $? -ne 0 ]
then
  exit $?
fi

echo "Note: You will probably need to wait 60 seconds for Orca to finish starting up."

