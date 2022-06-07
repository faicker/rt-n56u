#!/bin/sh

file=/etc/storage/chinadns/adhosts
reject_ip=0.0.0.0
tmpfile=/tmp/adhosts

to_hosts() {
	    ip=$1
	        tr '\n' ' ' | sed -e "s/^/$ip /" -e 's/ $/\n/'
	}

#ad list
url_reject_list="https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/reject-list.txt"

data=$(curl --retry 3 -4sSkL "$url_reject_list") || { echo "download $url_reject_list failed, exit-code: $?"; exit 1; }
echo "$data" | to_hosts $reject_ip > $tmpfile

mv -f $tmpfile $file

mtd_storage.sh save >/dev/null 2>&1

[ -f /usr/bin/shadowsocks.sh ] && [ "$(nvram get ss_enable)" = "1" ] && [ "$(nvram get ss_run_mode)" = "router" ] && /usr/bin/shadowsocks.sh restart >/dev/null 2>&1

logger -st "chinadns-ng" "adhosts Update done"
