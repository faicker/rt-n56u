#!/bin/sh

#linux tune
#some in start_script.sh
ulimit -n 4096
sysctl -w net.core.rmem_default=524288
sysctl -w net.core.wmem_default=212992
sysctl -w net.core.rmem_max=4194304
sysctl -w net.core.wmem_max=1048576
sysctl -w net.ipv4.tcp_rmem='4096 524288 4194304'
sysctl -w net.ipv4.tcp_wmem='4096 262144 4194304'
sysctl -w net.ipv4.tcp_mem='21159 28215 42318'
sysctl -w net.ipv4.udp_mem='42321 56431 84642'
sysctl -w net.core.netdev_max_backlog=4096
sysctl -w net.ipv4.tcp_max_syn_backlog=1024
sysctl -w net.ipv4.ip_local_port_range='10000 60999'

#nvram set ntp_ready=0
if [ $(nvram get sdns_enable) = 1 ] ; then
logger -t "自动启动" "正在启动SmartDns"
/usr/bin/smartdns.sh start
fi

if [ $(nvram get caddy_enable) = 1 ] ; then
logger -t "自动启动" "正在启动文件管理"
/usr/bin/caddy.sh start
fi

logger -t "自动启动" "正在检查路由是否已连接互联网！"
count=0
while :
do
	ping -c 1 -W 1 -q www.baidu.com 1>/dev/null 2>&1
	if [ "$?" == "0" ]; then
		break
	fi
	ping -c 1 -W 1 -q 202.108.22.5 1>/dev/null 2>&1
	if [ "$?" == "0" ]; then
		break
	fi
	sleep 5
	ping -c 1 -W 1 -q www.google.com 1>/dev/null 2>&1
	if [ "$?" == "0" ]; then
		break
	fi
	ping -c 1 -W 1 -q 8.8.8.8 1>/dev/null 2>&1
	if [ "$?" == "0" ]; then
		break
	fi
	sleep 5
	count=$((count+1))
	if [ $count -gt 18 ]; then
		break
	fi
done

if [ $(nvram get adbyby_enable) = 1 ] ; then
logger -t "自动启动" "正在启动adbyby plus+"
/usr/bin/adbyby.sh start
fi

if [ $(nvram get koolproxy_enable) = 1 ] ; then
logger -t "自动启动" "正在启动koolproxy"
/usr/bin/koolproxy.sh start
fi

if [ $(nvram get aliddns_enable) = 1 ] ; then
logger -t "自动启动" "正在启动阿里ddns"
/usr/bin/aliddns.sh start
fi

if [ $(nvram get ss_enable) = 1 ] ; then
logger -t "自动启动" "正在启动科学上网"
/usr/bin/shadowsocks.sh start
fi

if [ $(nvram get adg_enable) = 1 ] ; then
logger -t "自动启动" "正在启动adguardhome"
/usr/bin/adguardhome.sh start
fi

if [ $(nvram get wyy_enable) = 1 ] ; then
logger -t "自动启动" "正在启动音乐解锁"
/usr/bin/unblockmusic.sh start
fi

if [ $(nvram get zerotier_enable) = 1 ] ; then
logger -t "自动启动" "正在启动zerotier"
/usr/bin/zerotier.sh start
fi

#rps
logger -t "optimize" "rps"
cpu_number=`grep -c '^processor' /proc/cpuinfo`
v=$(( (1<<$cpu_number)-1 ))
v=`printf "%x" $v`
for nic in `/bin/ls -1 /sys/devices/virtual/net`;do
	echo $v > /sys/class/net/$nic/queues/rx-0/rps_cpus
	echo 4096 > /sys/class/net/$nic/queues/rx-0/rps_flow_cnt
done
