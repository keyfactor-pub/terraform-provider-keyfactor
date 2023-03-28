#!/usr/bin/env bash
export SECRET_NAME=terraform-provider-keyfactor-command-10-11
export VAULT_NAME=kf-integrations
export SECRET_ENCODING=ascii
export SECRET_PATH=.auto.tfvars
az keyvault secret set \
  --name $SECRET_NAME \
  --vault-name $VAULT_NAME \
  --file $SECRET_PATH --encoding $SECRET_ENCODING