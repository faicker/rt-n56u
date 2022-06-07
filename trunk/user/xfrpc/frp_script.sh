#!/bin/sh
#from hiboy
killall frpc
mkdir -p /tmp/frp
#启动frp功能后会运行以下脚本
#frp项目地址教程: https://github.com/fatedier/frp/blob/master/README_zh.md
#请自行修改 token 用于对客户端连接进行身份验证
# IP查询： http://119.29.29.29/d?dn=github.com

cat > "/tmp/frp/myfrpc.ini" <<-\EOF
# ==========客户端配置：==========
[common]
server_addr = 1192.0.0.3
server_port = 7000
token = 12345

#log_file = /dev/null
#log_level = info
#log_max_days = 3

[ssh]
remote_port = 6000
type = tcp
local_ip = 192.168.2.1
local_port = 22
# ====================
EOF

#启动：
frpc_enable=`nvram get frpc_enable`
if [ "$frpc_enable" = "1" ] ; then
    frpc -c /tmp/frp/myfrpc.ini 2>&1 &
fi
