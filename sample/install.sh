#!/bin/bash

cp -f journal-gateway-gelf /usr/bin/
cp -f ./misc/journal-gateway-gelf.service /etc/systemd/system/
cp -f ./misc/journal-gateway-gelf.conf /etc
