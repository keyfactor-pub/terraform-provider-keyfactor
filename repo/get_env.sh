#!/usr/bin/env bash
export SECRET_NAME=terraform-provider-keyfactor-command-10-11
export SECRET_ENCODING=ascii
export SECRET_PATH=.auto.tfvars
export AZ_RESOURCE_GROUP_NAME=integrations-infra
export AZ_STORAGE_ACCOUNT_NAME=tfprovidertests
export AZ_STORAGE_CONTAINER_NAME=terraform-provider-keyfactor-tfstate
export AZ_TENANT_ID=csspkioutlook.onmicrosoft.com
export AZ_VAULT_NAME=kf-integrations

# Set GITHUB_TOKEN
#source ~/.github-token

# Login to azure
#az login --tenant $AZ_TENANT_ID

ACCOUNT_KEY=$(az storage account keys list --resource-group $AZ_RESOURCE_GROUP_NAME --account-name $STORAGE_ACCOUNT_NAME --query '[0].value' -o tsv)
export ARM_ACCESS_KEY=$ACCOUNT_KEY
export GITHUB_OWNER=keyfactor-pub

# Get .auto.tfvars from azure keyvault
az keyvault secret download \
  --file $SECRET_PATH \
  --name $SECRET_NAME \
  --vault-name $AZ_VAULT_NAME