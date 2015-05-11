#!/bin/bash

cp -f journal-gateway-zmtp-control journal-gateway-zmtp-sink journal-gateway-zmtp-source /usr/bin/
cp -f ./misc/journal-gateway-zmtp-s*.service /etc/systemd/system/
cp -f ./misc/journal-gateway-zmtp-s*.conf /etc
