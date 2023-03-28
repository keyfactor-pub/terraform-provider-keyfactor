#!/usr/bin/env bash
# This file is used to set environment variables for running acceptance tests

# Setup Keyfactor Command Environment
#KEYFACTOR_HOSTNAME=""
#KEYFACTOR_USERNAME=""
#KEYFACTOR_PASSWORD=""
#KEYFACTOR_DOMAIN=""
#source ~/.env_kf-int-lab1011

# Create or empty .env file
echo "" > .env

# Use kfutil to find a random orchestrator to test with
export KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID=$(kfutil orchs list | jq -r ".[].AgentId" | tail -n 1) >> .env
export KEYFACTOR_CERTIFICATE_STORE_CLIENT_MACHINE=$(kfutil orchs list | jq -r ".[].ClientMachine" | tail -n 1) >> .env

# Use kfutil to find a random container to test with
# TODO=Remove hard-coded container names
export KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1=$(kfutil containers list | jq -r '.[] | select(.Name == "K8S Secret")' | jq -r .Id) >> .env
export KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID2=$(kfutil containers list | jq -r '.[] | select(.Name == "K8S TLS Secrets")' | jq -r .Id) >> .env

#kfutil stores list | \
#   jq -r --arg KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID="$KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID" \
#   '.[] | select(.AgentId == $KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID)' | \
#   jq -r --arg KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1="$KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1" \
#     '.[] |  select (.ContainerId == $KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1)' | jq -r '.[0]'

# Use kfutil to find a cert store compatible with the orchestrator and container
cert_store_resp=$(kfutil stores list | \
   jq -r --arg KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID="$KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID" \
   '.[] | select(.AgentId == $KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID)' | \
   jq -r --arg KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1="$KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1" \
     '.[] |  select (.ContainerId == $KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1)' | jq -r '.[0]')
     
export KEYFACTOR_CERTIFICATE_STORE_ID=$(echo "$cert_store_resp" | jq -r .Id)
export KEYFACTOR_CERTIFICATE_STORE_TYPE_ID=$(echo "$cert_store_resp" | jq -r .CertStoreType)
export KEYFACTOR_CERTIFICATE_STORE_TYPE=$(kfutil store-types list | jq --argjson var "$((KEYFACTOR_CERTIFICATE_STORE_TYPE_ID))" '.[] | select(.StoreType == $var)' | jq -r .Name)
export KEYFACTOR_CERTIFICATE_STORE_PATH=$(echo "$cert_store_resp" | jq -r .Storepath)

# Use kfutil to find a test cert
export KEYFACTOR_CERTIFICATE_ID="1011" #todo=pending kfutil cert list support
export KEYFACTOR_CERTIFICATE_PASSWORD="fake_demo_pass_changeme@!!"
export KEYFACTOR_CERTIFICATE_TEMPLATE_NAME="2YearTestWebServer" #todo=pending kfutil template list support
export KEYFACTOR_CERTIFICATE_CA_DOMAIN="DC-CA.Command.local" #todo=pending kfutil ca list support
export KEYFACTOR_CERTIFICATE_CA_NAME="CommandCA1" #todo=pending kfutil ca list support

# Choose Deployment Stores
KEYFACTOR_DEPLOY_CERT_STOREID1=$KEYFACTOR_CERTIFICATE_STORE_ID
KEYFACTOR_DEPLOY_CERT_STOREID2=$KEYFACTOR_CERTIFICATE_STORE_ID

# Use kfutil to find a random user account for tests
KEYFACTOR_SECURITY_IDENTITY_ACCOUNTNAME="acc-tests-terraformer"

# Use kfutil to find a random role for role binding tests
KEYFACTOR_SECURITY_IDENTITY_ROLE1="EnrollPFX"
KEYFACTOR_SECURITY_IDENTITY_ROLE2="Terraform"

# Use kfutil to find a random template for role binding tests
KEYFACTOR_TEMPLATE_ROLE_BINDING_ROLE_NAME="Terraform Acceptance Tests"
KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME1="2YearTestWebServer"
KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME2="Workstation"
KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME3="User"

printenv | grep KEYFACTOR > .env

