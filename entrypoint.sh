#!/bin/sh

set -eo pipefail

if [ -z "${VCAP_APPLICATION}" ]; then
  echo '$VCAP_APPLICATION must be set'
  exit 1
fi

if [ -z "${VCAP_SERVICES}" ]; then
  echo '$VCAP_SERVICES must be set'
  exit 1
fi

if ! echo ${VCAP_APPLICATION} | jq ".application_uris[0] != null" -e; then
  echo "The application must have a route"
  exit 1
fi

if ! echo ${VCAP_SERVICES} | jq ".elasticsearch[0] != null" -e; then
  echo "You must bind an elasticsearch service to this application"
  exit 1
fi

python3 -m sso-proxy &

/usr/share/kibana/bin/kibana --cpu.cgroup.path.override=/ --cpuacct.cgroup.path.override=/ \
  --server.host=127.0.0.1 \
  --server.port=5601 \
  --server.name=$(echo ${VCAP_APPLICATION} | jq ".application_uris[0]" -r) \
  --elasticsearch.url=https://$(echo ${VCAP_SERVICES} | jq ".elasticsearch[0].credentials.hostname" -r):$(echo ${VCAP_SERVICES} | jq ".elasticsearch[0].credentials.port" -r) \
  --elasticsearch.username=$(echo ${VCAP_SERVICES} | jq ".elasticsearch[0].credentials.username" -r) \
  --elasticsearch.password=$(echo ${VCAP_SERVICES} | jq ".elasticsearch[0].credentials.password" -r) &

while sleep 10; do
  ps aux |grep python3 |grep -q -v grep
  PYTHON_STATUS=$?
  ps aux |grep kibana |grep -q -v grep
  KIBANA_STATUS=$?
  if [ $PYTHON_STATUS -ne 0 ]; then
    echo "Python exited"
    exit 1
  fi
  if [ $KIBANA_STATUS -ne 0 ]; then
    echo "Kibana exited"
    exit 1
  fi
done
