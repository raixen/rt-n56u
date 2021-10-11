#!/bin/sh
#from aaron
killall npc
tmpconf="/tmp/npc/npc.conf"
LOGFILE="/tmp/npc.log"

if [ -f $tmpconf ] ; then
	rm $tmpconf
fi

npc_enable=`nvram get npc_enable`
server_addr=`nvram get npc_server_addr`
server_port=`nvram get npc_server_port`
protocol=`nvram get npc_protocol`
vkey=`nvram get npc_vkey`
compress=`nvram get npc_compress`
crypt=`nvram get npc_crypt`
Log_level=`nvram get npc_log_level`

echo "[common]" >$tmpconf
echo "server_addr=$server_addr:$server_port" >>$tmpconf
echo "conn_type=$protocol" >>$tmpconf
echo "vkey=$vkey" >>$tmpconf
echo "auto_reconnection=true" >>$tmpconf

if [ "$compress" = "1" ] ; then
	echo "compress=true" >>$tmpconf
else
	echo "compress=false" >>$tmpconf
fi

if [ "$crypt" = "1" ] ; then
	echo "crypt=true" >>$tmpconf
else
	echo "crypt=false" >>$tmpconf
fi

if [ "$npc_enable" = "1" ] ; then
	npc_bin="/usr/bin/npc"  #需要使用外部版本可删除此路径
	if [ ! -f "$npc_bin" ]; then
		if [ ! -f "/tmp/npc" ];then
		    logger -t "NPC" "开始下载npc二进制文件..."
			wget -c -O /tmp/npc https://raw.fastgit.org/etion2008/aaron/main/npc/npc
			[ $? != 0 ] && sleep 10 && wget -c -O /tmp/npc https://raw.fastgit.org/hiboyhiboy/opt-file/master/npc
			if [ ! -f "/tmp/npc" ] ;then
			    Latest_releases=`curl -skL https://api.github.com/repos/ehang-io/nps/releases/latest --connect-timeout 8 2>/dev/null |grep linux_mipsle_client.tar.gz |grep 'browser_download_url' |awk -F"github.com" '{print $NF}'|sed s/\"//`
			    Download_URL1="https://hub.fastgit.org${Latest_releases}"
			    Download_URL2="https://github.com${Latest_releases}"
			    logger -t "NPC" "开始下载npc最新版二进制文件..."
			    mkdir -p /tmp/NPC; wget -c -P /tmp/NPC $Download_URL1
			    [ $? != 0 ] && wget -c -P /tmp/npc $Download_URL2
			    tar -xzf /tmp/NPC/linux_mipsle_client.tar.gz -C /tmp/NPC/
			    \mv /tmp/NPC/npc /tmp/npc; rm -rf /tmp/NPC/
            fi
			if [ ! -f "/tmp/npc" ]; then
				logger -t "NPC" "npc二进制文件下载失败，可能是地址失效或者网络异常！请稍后再试"
				nvram set npc_enable=0
				npc_close
			else
				logger -t "NPC" "npc二进制文件下载成功"
				chmod -R 777 /tmp/npc
				npc_bin="/tmp/npc"
			fi
		else
			npc_bin="/tmp/npc"
		fi
	fi

	$npc_bin -config=$tmpconf -log_level=$Log_level -log_path=$LOGFILE -debug=false 2>&1 &
fi
