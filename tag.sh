#!/usr/bin/env bash
TAG_VERSION=v2.2.0-rc.8
git tag -d $TAG_VERSION || true
git push origin :$TAG_VERSION || true
git tag $TAG_VERSION
git push origin $TAG_VERSION
