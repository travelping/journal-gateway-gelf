#!/bin/bash

FILE=journal-gateway-gelf_mem-footprint-$(date +"%T")
# fresh start for journal-gateway-gelf
systemctl stop journal-gateway-gelf
sleep 1
systemctl start journal-gateway-gelf

# dump mem usage to file
top -cbn1|grep "\/usr\/bin\/[j]ournal-gateway-gelf" |tee -a $FILE

for i in {1..10000}; do
	echo "sending $i. batch of 100 log messages."
	for j in {1..1000}; do logger "This is test log number $(($i*100+$j))."; done
#	sleep 1
	top -cbn1|grep "\/usr\/bin\/[j]ournal-gateway-gelf" |tee -a $FILE
done
