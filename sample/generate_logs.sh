#!/bin/bash

i="0"

while true
do
logger logtest $i
sleep 1
i=$[$i+1]
done