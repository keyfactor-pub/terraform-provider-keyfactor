#!/usr/bin/env bash
set -e
make vendor
cd vendor/github.com/Keyfactor
rm -rf keyfactor-go-client || true
ln -s "$HOME/GolandProjects/keyfactor-go-client" .
rm -rf keyfactor-go-client-sdk || true
ln -s "$HOME/GolandProjects/keyfactor-go-client-sdk" .
rm -rf keyfactor-auth-client-go || true
ln -s "$HOME/GolandProjects/kfc-auth" keyfactor-auth-client-go
cd ../spbsoluble
rm -rf go-pkcs12 || true
ln -s "$HOME/GolandProjects/go-pkcs12" .
cd ../../..