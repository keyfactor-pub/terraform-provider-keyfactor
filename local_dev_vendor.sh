#!/usr/bin/env bash
make vendor
cd vendor/github.com/Keyfactor
rm -rf keyfactor-go-client
ln -s $GO_PATH/keyfactor-go-client .
cd ../../..