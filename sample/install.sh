#!/bin/bash

cp -f journal-gateway-gelf-source /usr/bin/
cp -f ./misc/journal-gateway-gelf-s*.service /etc/systemd/system/
cp -f ./misc/journal-gateway-gelf-s*.conf /etc
