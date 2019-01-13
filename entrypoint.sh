#!/bin/sh

set -eo pipefail

if [ -z "${PORT}" ]; then
  echo '$PORT must be set'
  exit 1
fi

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

exec \
  /usr/share/kibana/bin/kibana --cpu.cgroup.path.override=/ --cpuacct.cgroup.path.override=/ \
  --server.host=0.0.0.0 \
  --server.port=${PORT} \
  --server.name=$(echo ${VCAP_APPLICATION} | jq ".application_uris[0]" -r) \
  --elasticsearch.url=https://$(echo ${VCAP_SERVICES} | jq ".elasticsearch[0].credentials.hostname" -r):$(echo ${VCAP_SERVICES} | jq ".elasticsearch[0].credentials.port" -r) \
  --elasticsearch.username=$(echo ${VCAP_SERVICES} | jq ".elasticsearch[0].credentials.username" -r) \
  --elasticsearch.password=$(echo ${VCAP_SERVICES} | jq ".elasticsearch[0].credentials.password" -r)
