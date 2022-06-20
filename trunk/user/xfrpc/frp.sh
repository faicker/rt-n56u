#!/bin/sh
frpc_enable=`nvram get frpc_enable`
http_username=`nvram get http_username`

check_frp () 
{
	check_net
	result_net=$?
	if [ "$result_net" = "1" ] ;then
		if [ -z "`pidof frpc`" ] && [ "$frpc_enable" = "1" ];then
			frp_start
		fi
	fi
}

check_net() 
{
	/bin/ping -c 3 223.5.5.5 -w 5 >/dev/null 2>&1
	if [ "$?" == "0" ]; then
		return 1
	else
		return 2
		logger -t "frp" "检测到互联网未能成功访问,稍后再尝试启动frp"
	fi
}

frp_start () 
{
	if [ "$frpc_enable" = "1" ]; then
		/etc/storage/frp_script.sh
		sed -i '/frp/d' /etc/storage/cron/crontabs/$http_username
		cat >> /etc/storage/cron/crontabs/$http_username << EOF
*/1 * * * * /bin/sh /usr/bin/frp.sh C >/dev/null 2>&1
EOF
		[ ! -z "`pidof frpc`" ] && logger -t "frp" "frpc启动成功"
	fi
}

frp_close () 
{
	if [ "$frpc_enable" = "0" ]; then
		if [ ! -z "`pidof frpc`" ]; then
			killall -9 frpc frp_script.sh
			usleep 200000
			[ -z "`pidof frpc`" ] && logger -t "frp" "已停止 frpc"
		fi
		sed -i '/frp/d' /etc/storage/cron/crontabs/$http_username
	fi
}


case $1 in
start)
	frp_start
	;;
stop)
	frp_close
	;;
C)
	check_frp
	;;
esac
