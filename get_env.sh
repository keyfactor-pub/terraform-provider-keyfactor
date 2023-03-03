#!/usr/bin/env bash
source ~/.env_kf-int-lab1011
export KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID=$(kfutil orchs list | jq -r ".[].AgentId" | tail -n 1) >> .env
export KEYFACTOR_CERTIFICATE_STORE_CLIENT_MACHINE=$(kfutil orchs list | jq -r ".[].ClientMachine" | tail -n 1) >> .env
export KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1=$(kfutil containers list | jq -r '.[] | select(.Name == "K8S Secret")' | jq -r .Id) >> .env
export KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID2=$(kfutil containers list | jq -r '.[] | select(.Name == "K8S TLS Secrets")' | jq -r .Id) >> .env


export KEYFACTOR_CERT_STORE=$(kfutil stores list | \
                             jq -r --arg KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID="$KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID" \
                             '.[] | select(.AgentId == $KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID)' | \
                             jq -r --arg KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1="$KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1" \
                               '.[] |  select (.ContainerId == $KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1)' | jq -r '.[0]')
export KEYFACTOR_CERTIFICATE_STORE_ID=$(echo "$KEYFACTOR_CERT_STORE" | jq -r .Id)
export KEYFACTOR_CERTIFICATE_STORE_TYPE_ID=$(echo "$KEYFACTOR_CERT_STORE" | jq -r .CertStoreType)
export KEYFACTOR_CERTIFICATE_STORE_TYPE=$(kfutil stores types list | jq -r --arg KEYFACTOR_CERTIFICATE_STORE_TYPE_ID "$KEYFACTOR_CERTIFICATE_STORE_TYPE_ID" '.[] | select(.Id == $KEYFACTOR_CERTIFICATE_STORE_TYPE_ID)' | jq -r .Name)
echo "$KEYFACTOR_CERT_STORE" | jq -r
export KEYFACTOR_CERTIFICATE_STORE_PATH=$(echo "$KEYFACTOR_CERT_STORE" | jq -r .Path)
printenv | grep KEYFACTOR > .env
