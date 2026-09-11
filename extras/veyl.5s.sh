#!/bin/sh
# SwiftBar / xbar plugin: menu-bar toggle, as a replacement for the hand-built
# Swift app. The app had to own ciadpi's lifecycle to work; this only writes a
# boolean, so ciadpi stays a launchd daemon and the boot-time stranded-setting
# failure stays impossible.
#
# Install: cp into your SwiftBar plugin folder (keep the .5s. refresh interval).

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
