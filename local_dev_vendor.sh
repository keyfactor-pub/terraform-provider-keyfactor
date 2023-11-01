#!/usr/bin/env bash
make vendor
mkdir -p vendor/github.com/Keyfactor
cd vendor/github.com/Keyfactor
rm -rf keyfactor-go-client
rm -rf keyfactor-go-client-sdk
ln -s /Users/sbailey/GolandProjects/keyfactor-go-client .
ln -s /Users/sbailey/GolandProjects/keyfactor-go-client-sdk .
cd ../../..