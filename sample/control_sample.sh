#!/bin/bash

# mkfifo /tmp/control_input
# ./journal-gateway-zmtp-control < /tmp/control_input &
# echo "help" > /tmp/control_input
# sleep 2
# echo "show_sources"
# sleep 2


echo "show_sources" | ./journal-gateway-zmtp-control
sleep 2
echo "\nChanging the filter\n"
echo "filter [[\"MESSAGE=NOMESSAGE\"]]" | ./journal-gateway-zmtp-control
sleep 2
echo "show_filter" | ./journal-gateway-zmtp-control
sleep 2
echo "\nNow apply the new filter\n"
echo "send_query" | ./journal-gateway-zmtp-control
sleep 2
echo "\nDeactivate the filter"
echo "filter" | ./journal-gateway-zmtp-control
sleep 2
echo "show_filter" | ./journal-gateway-zmtp-control
sleep 1
echo "\nNow apply this non-filter\n"
echo "send_query" | ./journal-gateway-zmtp-control
