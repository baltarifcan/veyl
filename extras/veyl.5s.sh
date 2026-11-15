#!/bin/sh
# SwiftBar/xbar menu-bar toggle. Copy into your plugin folder.

STATE=/Users/Shared/.veyl-enabled

if [ "$(cat "$STATE" 2>/dev/null)" = 1 ]; then
    echo ":lock.shield.fill: | sfcolor=green"
    echo "---"
    echo "veyl is on"
    echo "Turn off | shell=/bin/sh param1=-c param2=\"echo 0 > $STATE\" terminal=false refresh=true"
else
    echo ":lock.open: | sfcolor=secondary"
    echo "---"
    echo "veyl is off"
    echo "Turn on | shell=/bin/sh param1=-c param2=\"echo 1 > $STATE\" terminal=false refresh=true"
fi
