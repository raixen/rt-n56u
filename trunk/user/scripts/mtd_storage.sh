#!/bin/sh

result=0
mtd_part_name="Storage"
mtd_part_dev="/dev/mtdblock5"
mtd_part_size=65536
dir_storage="/etc/storage"
slk="/tmp/.storage_locked"
tmp="/tmp/storage.tar"
tbz="${tmp}.bz2"
hsh="/tmp/hashes/storage_md5"

func_get_mtd()
{
	local mtd_part mtd_char mtd_idx mtd_hex
	mtd_part=`cat /proc/mtd | grep \"$mtd_part_name\"`
	mtd_char=`echo $mtd_part | cut -d':' -f1`
	mtd_hex=`echo $mtd_part | cut -d' ' -f2`
	mtd_idx=`echo $mtd_char | cut -c4-5`
	if [ -n "$mtd_idx" ] && [ $mtd_idx -ge 4 ] ; then
		mtd_part_dev="/dev/mtdblock${mtd_idx}"
		mtd_part_size=`echo $((0x$mtd_hex))`
	else
		logger -t "Storage" "Cannot find MTD partition: $mtd_part_name"
		exit 1
	fi
}

func_mdir()
{
	[ ! -d "$dir_storage" ] && mkdir -p -m 755 $dir_storage
}

func_stop_apps()
{
	killall -q rstats
	[ $? -eq 0 ] && sleep 1
}

func_start_apps()
{
	/sbin/rstats
}

func_load()
{
	local fsz

	bzcat $mtd_part_dev > $tmp 2>/dev/null
	fsz=`stat -c %s $tmp 2>/dev/null`
	if [ -n "$fsz" ] && [ $fsz -gt 0 ] ; then
		md5sum $tmp > $hsh
		tar xf $tmp -C $dir_storage 2>/dev/null
	else
		result=1
		rm -f $hsh
		logger -t "Storage load" "Invalid storage data in MTD partition: $mtd_part_dev"
	fi
	rm -f $tmp
	rm -f $slk
}

func_tarb()
{
	rm -f $tmp
	cd $dir_storage
	find * -print0 | xargs -0 touch -c -h -t 201001010000.00
	find * ! -type d -print0 | sort -z | xargs -0 tar -cf $tmp 2>/dev/null
	cd - >>/dev/null
	if [ ! -f "$tmp" ] ; then
		logger -t "Storage" "Cannot create tarball file: $tmp"
		exit 1
	fi
}

func_save()
{
	local fsz

	logger -t "Storage save" "Save storage files to MTD partition \"$mtd_part_dev\""
	echo "Save storage files to MTD partition \"$mtd_part_dev\""
	rm -f $tbz
	md5sum -c -s $hsh 2>/dev/null
	if [ $? -eq 0 ] ; then
		echo "Storage hash is not changed, skip write to MTD partition. Exit."
		rm -f $tmp
		return 0
	fi
	md5sum $tmp > $hsh
	bzip2 -9 $tmp 2>/dev/null
	fsz=`stat -c %s $tbz 2>/dev/null`
	if [ -n "$fsz" ] && [ $fsz -ge 16 ] && [ $fsz -le $mtd_part_size ] ; then
		mtd_write write $tbz $mtd_part_name
		if [ $? -eq 0 ] ; then
			echo "Done."
			logger -t "Storage save" "Done."
		else
			result=1
			echo "Error! MTD write FAILED"
			logger -t "Storage save" "Error write to MTD partition: $mtd_part_dev"
		fi
	else
		result=1
		echo "Error! Invalid storage final data size: $fsz"
		logger -t "Storage save" "Invalid storage final data size: $fsz"
	fi
	rm -f $tmp
	rm -f $tbz
}

func_backup()
{
	rm -f $tbz
	bzip2 -9 $tmp 2>/dev/null
	if [ $? -ne 0 ] ; then
		result=1
		logger -t "Storage backup" "Cannot create BZ2 file!"
	fi
	rm -f $tmp
}

func_restore()
{
	local fsz tmp_storage

	[ ! -f "$tbz" ] && exit 1

	fsz=`stat -c %s $tbz 2>/dev/null`
	if [ -z "$fsz" ] || [ $fsz -lt 16 ] || [ $fsz -gt $mtd_part_size ] ; then
		result=1
		rm -f $tbz
		logger -t "Storage restore" "Invalid BZ2 file size: $fsz"
		return 1
	fi

	tmp_storage="/tmp/storage"
	rm -rf $tmp_storage
	mkdir -p -m 755 $tmp_storage
	tar xjf $tbz -C $tmp_storage 2>/dev/null
	if [ $? -ne 0 ] ; then
		result=1
		rm -f $tbz
		rm -rf $tmp_storage
		logger -t "Storage restore" "Unable to extract BZ2 file: $tbz"
		return 1
	fi
	if [ ! -f "$tmp_storage/start_script.sh" ] ; then
		result=1
		rm -f $tbz
		rm -rf $tmp_storage
		logger -t "Storage restore" "Invalid content of BZ2 file: $tbz"
		return 1
	fi

	func_stop_apps

	rm -f $slk
	rm -f $tbz
	rm -rf $dir_storage
	mkdir -p -m 755 $dir_storage
	cp -rf $tmp_storage /etc
	rm -rf $tmp_storage

	func_start_apps
}

func_erase()
{
	mtd_write erase $mtd_part_name
	if [ $? -eq 0 ] ; then
		rm -f $hsh
		rm -rf $dir_storage
		mkdir -p -m 755 $dir_storage
		touch "$slk"
	else
		result=1
	fi
}

func_reset()
{
	rm -f $slk
	rm -rf $dir_storage
	mkdir -p -m 755 $dir_storage
}

func_fill()
{
	dir_httpssl="$dir_storage/https"
	dir_dnsmasq="$dir_storage/dnsmasq"
	dir_ovpnsvr="$dir_storage/openvpn/server"
	dir_ovpncli="$dir_storage/openvpn/client"
	dir_sswan="$dir_storage/strongswan"
	dir_sswan_crt="$dir_sswan/ipsec.d"
	dir_inadyn="$dir_storage/inadyn"
	dir_crond="$dir_storage/cron/crontabs"
	dir_wlan="$dir_storage/wlan"
	dir_chnroute="$dir_storage/chinadns"
	#dir_gfwlist="$dir_storage/gfwlist"

	script_start="$dir_storage/start_script.sh"
	script_started="$dir_storage/started_script.sh"
	script_shutd="$dir_storage/shutdown_script.sh"
	script_postf="$dir_storage/post_iptables_script.sh"
	script_postw="$dir_storage/post_wan_script.sh"
	script_inets="$dir_storage/inet_state_script.sh"
	script_vpnsc="$dir_storage/vpns_client_script.sh"
	script_vpncs="$dir_storage/vpnc_server_script.sh"
	script_ezbtn="$dir_storage/ez_buttons_script.sh"
	script_aps="$dir_storage/ap_script.sh"

	user_hosts="$dir_dnsmasq/hosts"
	user_dnsmasq_conf="$dir_dnsmasq/dnsmasq.conf"
	user_dhcp_conf="$dir_dnsmasq/dhcp.conf"
	user_ovpnsvr_conf="$dir_ovpnsvr/server.conf"
	user_ovpncli_conf="$dir_ovpncli/client.conf"
	user_inadyn_conf="$dir_inadyn/inadyn.conf"
	user_sswan_conf="$dir_sswan/strongswan.conf"
	user_sswan_ipsec_conf="$dir_sswan/ipsec.conf"
	user_sswan_secrets="$dir_sswan/ipsec.secrets"
	
	chnroute_file="/etc_ro/chnroute.bz2"
	#gfwlist_conf_file="/etc_ro/gfwlist.bz2"

	# create crond dir
	[ ! -d "$dir_crond" ] && mkdir -p -m 730 "$dir_crond"

	# create https dir
	[ ! -d "$dir_httpssl" ] && mkdir -p -m 700 "$dir_httpssl"

	# create chnroute.txt
	if [ ! -d "$dir_chnroute" ] ; then
		if [ -f "$chnroute_file" ]; then
			mkdir -p "$dir_chnroute" && tar jxf "$chnroute_file" -C "$dir_chnroute"
		fi
	fi

	# create gfwlist
	#if [ ! -d "$dir_gfwlist" ] ; then
	#	if [ -f "$gfwlist_conf_file" ]; then	
#			mkdir -p "$dir_gfwlist" && tar jxf "$gfwlist_conf_file" -C "$dir_gfwlist"
	#	fi
#	fi

	# create start script
	if [ ! -f "$script_start" ] ; then
		reset_ss.sh -a
	fi

	# create started script
	if [ ! -f "$script_started" ] ; then
		cat > "$script_started" <<'EOF'
#!/bin/sh

### Custom user script
### Called after router started and network is ready

### Example - load ipset modules
#modprobe ip_set
#modprobe ip_set_hash_ip
#modprobe ip_set_hash_net
#modprobe ip_set_bitmap_ip
#modprobe ip_set_list_set
#modprobe xt_set

#drop caches
sync && echo 3 > /proc/sys/vm/drop_caches

# Roaming assistant for mt76xx WiFi
#iwpriv ra0 set KickStaRssiLow=-85
#iwpriv ra0 set AssocReqRssiThres=-80
#iwpriv rai0 set KickStaRssiLow=-85
#iwpriv rai0 set AssocReqRssiThres=-80
>>>>>>> a321e6940bb0cb44619e21b8b3df6e91f892751a

# Mount SATA disk
#mdev -s

#wing <HOST:443> <PASS>
#wing 192.168.1.9:1080
#ipset add gfwlist 8.8.4.4


EOF
		chmod 755 "$script_started"
	fi

	# create shutdown script
	if [ ! -f "$script_shutd" ] ; then
		cat > "$script_shutd" <<EOF
#!/bin/sh

### Custom user script
### Called before router shutdown
### \$1 - action (0: reboot, 1: halt, 2: power-off)

EOF
		chmod 755 "$script_shutd"
	fi

	# create post-iptables script

	if [ ! -f "$script_postf" ] ; then
		cat > "$script_postf" <<EOF
#!/bin/sh

### Custom user script
### Called after internal iptables reconfig (firewall update)

#wing resume

EOF
		chmod 755 "$script_postf"
	fi

	# create post-wan script
	if [ ! -f "$script_postw" ] ; then
		cat > "$script_postw" <<EOF
#!/bin/sh

### Custom user script
### Called after internal WAN up/down action
### \$1 - WAN action (up/down)
### \$2 - WAN interface name (e.g. eth3 or ppp0)
### \$3 - WAN IPv4 address

EOF
		chmod 755 "$script_postw"
	fi

	# create inet-state script
	if [ ! -f "$script_inets" ] ; then
		cat > "$script_inets" <<EOF
#!/bin/sh
#/etc/storage/inet_state_script.sh
### Custom user script
### Called on Internet status changed
### $1 - Internet status (0/1)
### $2 - elapsed time (s) from previous state
logger -t "【网络检测】" "互联网状态:$1, 经过时间:$2s."

if [ $1 != "0" ] ; then
    #网络畅通
    mtk_gpio -w 13 0   #关闭红灯
    mtk_gpio -w 14 1   #关闭黄灯
    mtk_gpio -w 15 0   #开启蓝灯
    logger -t "【网络检测】" "网络已连接，关闭LED灯"
    exit
else
    #网络不通
    mtk_gpio -w 13 0   #开启红灯
    mtk_gpio -w 15 1   #关闭蓝灯
    mtk_gpio -w 14 0   #开启黄灯
    logger -t "【网络检测】" "互联网已断开，已切换黄灯"
    [ ! -s /tmp/ap2g5g ] && exit #判断是否需要执行下面的【自动切换】脚本
fi


# 【自动切换中继信号】功能 需要到【无线网络 - 无线桥接】页面配置脚本参数
#  脚本开始，以下内容无需修改

. /etc/storage/ap_script.sh
baidu='http://gb.corp.163.com/gb/images/spacer.gif'
aptimes="$1"
if [ $((aptimes)) -gt "9" ] ; then
    logger -t "【连接AP】" "$1秒后, 自动搜寻 ap"
    sleep $1
else
    logger -t "【连接AP】" "10秒后, 自动搜寻 ap"
    sleep 10
fi
cat /tmp/ap2g5g.txt | grep -v '^#'  | grep -v "^$" > /tmp/ap2g5g
if [ ! -f /tmp/apc.lock ] && [ "$1" != "1" ] && [ -s /tmp/ap2g5g ] ; then
    touch /tmp/apc.lock
    a2="$(iwconfig apcli0 | awk -F'"' '/ESSID/ {print $2}')"
    a5="$(iwconfig apclii0 | awk -F'"' '/ESSID/ {print $2}')"
    [ "$a2" = "" -a "$a5" = "" ] && ap=1 || ap=0
    if [ "$ap" = "1" ] || [ "$2" = "t" ] && [ -f /tmp/apc.lock ] ; then
        #搜寻开始/tmp/ap2g5g
        while read line
        do
        c_line=`echo "$line" | grep -v '^#' | grep -v "^$"`
        if [ ! -z "$c_line" ] ; then
            apc="$line"
            radio=$(echo "$apc" | cut -d $fenge -f1)

            # ApCli 2.4Ghz
            if [ "$radio" = "2" ] ; then
                rtwlt_mode_x=`nvram get rt_mode_x`
            else
                rtwlt_mode_x=`nvram get wl_mode_x`
            fi
            # [ "$rtwlt_mode_x" = "3" ] || [ "$rtwlt_mode_x" = "4" ] &&

            rtwlt_mode_x="$(echo "$apc" | cut -d $fenge -f2)"
            rtwlt_sta_wisp="$(echo "$apc" | cut -d $fenge -f3)"
            rtwlt_sta_ssid="$(echo "$apc" | cut -d $fenge -f4)"
            rtwlt_sta_wpa_psk="$(echo "$apc" | cut -d $fenge -f5)"
            rtwlt_sta_bssid="$(echo "$apc" | cut -d $fenge -f6 | tr 'A-Z' 'a-z')"
            if [ "$radio" = "2" ] ; then
                ap="$(iwconfig | grep 'apcli0' | grep ESSID:"$rtwlt_sta_ssid" | wc -l)"
                if [ "$ap" = "0" ] ; then
                    ap="$(iwconfig |sed -n '/apcli0/,/Rate/{/apcli0/n;/Rate/b;p}' | grep $rtwlt_sta_bssid | tr 'A-Z' 'a-z' | wc -l)"
                fi
            else
                ap="$(iwconfig | grep 'apclii0' | grep ESSID:"$rtwlt_sta_ssid" | wc -l)"
                if [ "$ap" = "0" ] ; then
                    ap="$(iwconfig |sed -n '/apclii0/,/Rate/{/apclii0/n;/Rate/b;p}' | grep $rtwlt_sta_bssid | tr 'A-Z' 'a-z' | wc -l)"
                fi
            fi

            if [ "$ap" = "1" ] ; then
                logger -t "【连接AP】" "当前是 $rtwlt_sta_ssid, 停止搜寻"
                rm -f /tmp/apc.lock
                if [ $((aptime)) -ge "9" ] ; then
                    /etc/storage/inet_state_script.sh $aptime "t" &
                    sleep 2
                    logger -t "【连接AP】" "直到连上最优先信号 $(echo $(grep -v '^#' /tmp/ap2g5g | grep -v "^$" | head -1) | cut -d $fenge -f4)"
                fi
                exit
            else
                logger -t "【连接AP】" "自动搜寻 $rtwlt_sta_ssid"
            fi
            if [ "$radio" = "2" ] ; then
            # ApCli 2.4Ghz
                iwpriv ra0 set SiteSurvey=1
                sleep 1
                if                     [ ! -z "$rtwlt_sta_bssid" ] ; then
                    logger -t "【连接AP】" "自动搜寻 $rtwlt_sta_ssid:$rtwlt_sta_bssid"
                    site_survey="$(iwpriv ra0 get_site_survey | sed -n "/$rtwlt_sta_bssid/p" | tr 'A-Z' 'a-z')"
                else
                    site_survey="$(iwpriv ra0 get_site_survey | sed -n "/$rtwlt_sta_ssid/p" | tr 'A-Z' 'a-z')"
                fi
            else
                iwpriv rai0 set SiteSurvey=1
                sleep 1
                if [ ! -z "$rtwlt_sta_bssid" ] ; then
                    logger -t "【连接AP】" "自动搜寻 $rtwlt_sta_ssid:$rtwlt_sta_bssid"
                    site_survey="$(iwpriv rai0 get_site_survey | sed -n "/$rtwlt_sta_bssid/p" | tr 'A-Z' 'a-z')"
                else
                    site_survey="$(iwpriv rai0 get_site_survey | sed -n "/$rtwlt_sta_ssid/p" | tr 'A-Z' 'a-z')"
                fi
            fi
            if [ -z "$site_survey" ] ; then
                logger -t "【连接AP】" "没找到 $rtwlt_sta_ssid, 如果含中文请填写正确的MAC地址"
                ap3=1
            fi
            if [ ! -z "$site_survey" ] ; then
                Ch=`echo "${site_survey:0:4}" | awk -F ' ' '{print $1}'`
                BSSID=`echo "${site_survey:37:20}" | awk -F ' ' '{print $1}'`
                Security=`echo "${site_survey:57:23}" | awk -F ' ' '{print $1}'`
                Signal=`echo "${site_survey:80:9}" | awk -F ' ' '{print $1}'`
                WMode=`echo "${site_survey:89:9}" | awk -F ' ' '{print $1}'`
                ap3=0
                if [ $Signal -lt $sig ]; then
                    logger -t "【连接AP】" "跳过$rtwlt_sta_ssid；信号强度 $Signal%，低于设置的 $sig%"
                    ap3=1
                fi
            fi
            if [ "$apblack" = "1" ] ; then
                apblacktxt=$(grep "【SSID:$rtwlt_sta_bssid" /tmp/apblack.txt)
                if [ ! -z $apblacktxt ] ; then
                    logger -t "【连接AP】" "当前是黑名单 $rtwlt_sta_ssid, 跳过黑名单继续搜寻"
                    ap3=1
                else
                    apblacktxt=$(grep "【SSID:$rtwlt_sta_ssid" /tmp/apblack.txt)
                    if [ ! -z $apblacktxt ] ; then
                        logger -t "【连接AP】" "当前是黑名单 $rtwlt_sta_ssid, 跳过黑名单继续搜寻"
                        ap3=1
                    fi
                fi
            fi
            if [ "$ap3" != "1" ] ; then
                if [[ $(expr $Security : ".*none*") -gt "1" ]] ; then
                    rtwlt_sta_auth_mode="open"
                    rtwlt_sta_wpa_mode="0"
                fi
                if [[ $(expr $Security : ".*1psk*") -gt "1" ]] ; then
                    rtwlt_sta_auth_mode="psk"
                    rtwlt_sta_wpa_mode="1"
                fi
                if [[ $(expr $Security : ".*2psk*") -gt "1" ]] ; then
                    rtwlt_sta_auth_mode="psk"
                    rtwlt_sta_wpa_mode="2"
                fi
                if [[ $(expr $Security : ".*wpapsk*") -gt "1" ]] ; then
                    rtwlt_sta_auth_mode="psk"
                    rtwlt_sta_wpa_mode="1"
                fi
                if [[ $(expr $Security : ".*tkip*") -gt "1" ]] ; then
                    rtwlt_sta_crypto="tkip"
                fi
                if [[ $(expr $Security : ".*aes*") -gt "1" ]] ; then
                    rtwlt_sta_crypto="aes"
                fi
                i=0
                if [ "$radio" = "2" ] ; then
                    nvram set rt_channel=$Ch
                    iwpriv apcli0 set Channel=$Ch
                    nvram set wl_mode_x=0 # 关闭 5Ghz 中继
                    nvram set rt_mode_x="$rtwlt_mode_x"
                    nvram set rt_sta_wisp="$rtwlt_sta_wisp"
                    nvram set rt_sta_ssid="$rtwlt_sta_ssid"
                    nvram set rt_sta_auth_mode="$rtwlt_sta_auth_mode"
                    nvram set rt_sta_wpa_mode="$rtwlt_sta_wpa_mode"
                    nvram set rt_sta_crypto="$rtwlt_sta_crypto"
                    nvram set rt_sta_wpa_psk="$rtwlt_sta_wpa_psk"
                    #强制20MHZ
                    #nvram set rt_HT_BW=0
                    nvram commit
                    radio2_restart
                    while [ $i -lt $connect_ap ]; do
                        sleep 1
                        ap=`iwconfig | grep 'apcli0' | grep 'ESSID:""' | wc -l`
                        if [ "$ap" = "0" ] ; then break; fi
                        i=$(( i+1 ))
                    done
                else
                    nvram set wl_channel=$Ch
                    iwpriv apclii0 set Channel=$Ch
                    nvram set rt_mode_x=0 # 关闭 2.4Ghz 中继
                    nvram set wl_mode_x="$rtwlt_mode_x"
                    nvram set wl_sta_wisp="$rtwlt_sta_wisp"
                    nvram set wl_sta_ssid="$rtwlt_sta_ssid"
                    nvram set wl_sta_auth_mode="$rtwlt_sta_auth_mode"
                    nvram set wl_sta_wpa_mode="$rtwlt_sta_wpa_mode"
                    nvram set wl_sta_crypto="$rtwlt_sta_crypto"
                    nvram set wl_sta_wpa_psk="$rtwlt_sta_wpa_psk"
                    nvram commit
                    radio5_restart
                    while [ $i -lt $connect_ap ]; do
                        sleep 1
                        ap=`iwconfig | grep 'apclii0' | grep 'ESSID:""' | wc -l`
                        if [ "$ap" = "0" ] ; then break; fi
                        i=$(( i+1 ))
                    done
                fi
                logger -t "【连接AP】" "【中继模式:$rtwlt_mode_x $rtwlt_sta_wisp】【Security:$Security】【WMode:$WMode】"
                logger -t "【连接AP】" "【AP:$rtwlt_sta_ssid】【密码:$rtwlt_sta_wpa_psk】【信号:$Signal%】【信道:$Ch】【BSSID:$BSSID】"
                if [ "$ap" = "0" ] && [ "$apauto2" = "1" ] ; then
                sleep 2
                    i=0 ping_text="" ping_time=1
                    while [ $i -lt $connect_net ]; do
                        sleep 2
                        ping_text=`ping -4 114.114.114.114 -c 1 -w 2 -q`
                        ping_time=`echo $ping_text | awk -F '/' '{print $4}'| awk -F '.' '{print $1}'`
                        if [ ! -z "$ping_time" ]; then break; fi
                        i=$(( i+1 ))
                    done
                    ping_loss=`echo $ping_text | awk -F ', ' '{print $3}' | awk '{print $1}'`
                    if [ ! -z "$ping_time" ] ; then
                        echo "ping：$ping_time ms 丢包率：$ping_loss"
                     else
                        echo "ping：失效"
                    fi
                    if [ ! -z "$ping_time" ] ; then
                        logger -t "【连接AP】" "$ap 已连接上 $rtwlt_sta_ssid, 成功联网"
                        ap=0
                    else
                        ap=1
                        logger -t "【连接AP】" "$ap 已连接上 $rtwlt_sta_ssid, 但未联网, 跳过继续搜寻"
                    fi
                fi
                if [ "$ap" = "1" ] ; then
                    logger -t "【连接AP】" "$ap 无法连接 $rtwlt_sta_ssid"
                else
                    logger -t "【连接AP】" "$ap 已连接上 $rtwlt_sta_ssid"
                    if [ "$apblack" = "1" ] ; then
                        i=0 ping_text="" ping_time=1
                        while [ $i -lt $connect_net ]; do
                            sleep 2
                            ping_text=`ping -4 114.114.114.114 -c 1 -w 2 -q`
                            ping_time=`echo $ping_text | awk -F '/' '{print $4}'| awk -F '.' '{print $1}'`
                            if [ ! -z "$ping_time" ]; then break; fi
                            i=$(( i+1 ))
                        done
                        ping_loss=`echo $ping_text | awk -F ', ' '{print $3}' | awk '{print $1}'`
                        if [ ! -z "$ping_time" ] ; then
                            echo "ping：$ping_time ms 丢包率：$ping_loss"
                         else
                            echo "ping：失效"
                        fi
                        if [ ! -z "$ping_time" ] ; then
                        echo "online"
                        else
                            apblacktxt="$ap AP不联网列入黑名单:【Ch:$Ch】【SSID:$rtwlt_sta_ssid】【BSSID:$BSSID】【Security:$Security】【Signal(%):$Signal】【WMode:$WMode】"
                            logger -t "【连接AP】" "$apblacktxt"
                            echo $apblacktxt >> /tmp/apblack.txt
                            rm -f /tmp/apc.lock
                            /etc/storage/inet_state_script.sh 0 "t" &
                            sleep 2
                            logger -t "【连接AP】" "跳过黑名单继续搜寻, 直到连上最优先信号 $(echo $(grep -v '^#' /tmp/ap2g5g | grep -v "^$" | head -1) | cut -d $fenge -f4)"
                            exit
                        fi
                    fi
                    if [ "$rtwlt_sta_ssid" = $(echo $(grep -v '^#' /tmp/ap2g5g | grep -v "^$" | head -1) | cut -d $fenge -f4) ] ; then
                        logger -t "【连接AP】" "当前是 $rtwlt_sta_ssid, 停止搜寻"
                        rm -f /tmp/apc.lock
                        logger -t "【连接AP】" "当前连上最优先信号 $rtwlt_sta_ssid"
                        exit
                    else
                        rm -f /tmp/apc.lock
                        if [ $((aptime)) -ge "9" ] ; then
                            /etc/storage/inet_state_script.sh $aptime "t" &
                            sleep 2
                            logger -t "【连接AP】" "直到连上最优先信号 $(echo $(grep -v '^#' /tmp/ap2g5g | grep -v "^$" | head -1) | cut -d $fenge -f4)"
                        fi
                        exit
                    fi
                fi
            fi
            sleep 5
        fi
        a2=`iwconfig apcli0 | awk -F'"' '/ESSID/ {print $2}'`
        a5=`iwconfig apclii0 | awk -F'"' '/ESSID/ {print $2}'`
        [ "$a2" = "" -a "$a5" = "" ] && ap=1 || ap=0
        sleep 2
        done < /tmp/ap2g5g
        sleep 40
        rm -f /tmp/apc.lock
        if [ "$ap" = "1" ] || [ "$2" = "t" ] && [ -f /tmp/apc.lock ] ; then
            #搜寻开始/tmp/ap2g5g
            /etc/storage/inet_state_script.sh 0 "t" &
            sleep 2
            logger -t "【连接AP】" "继续搜寻"
            exit
        fi
        sleep 1
    fi
    rm -f /tmp/apc.lock
    sleep 1
fi
killall sh_apauto.sh
if [ -s /tmp/ap2g5g ] ; then
    /tmp/sh_apauto.sh &
else
    echo "" > /tmp/apauto.lock
fi
logger -t "【连接AP】" "脚本完成"


EOF
		chmod 755 "$script_inets"
	fi

	# create ap_script script
	if [ ! -f "$script_aps" ] ; then
		cat > "$script_aps" <<EOF
#!/bin/sh
#/etc/storage/ap_script.sh
#copyright by hiboy

# AP中继连接守护功能。【0】 Internet互联网断线后自动搜寻；【1】 当中继信号断开时启动自动搜寻。
apauto=0

# AP连接成功条件，【0】 连上AP即可，不检查是否联网；【1】 连上AP并连上Internet互联网。
apauto2=0

# 【0】 联网断线后自动搜寻，大于【10】时则每隔【N】秒搜寻(无线网络会瞬断一下)，直到连上最优先信号。
aptime="0"

# 如搜寻的AP不联网则列入黑名单/tmp/apblack.txt 功能 【0】关闭；【1】启动
# 控制台输入【echo "" > /tmp/apblack.txt】可以清空黑名单
apblack=0

fenge='@'         # 自定义分隔符号，默认为【@】，注意:下面配置一同修改
connect_ap=100    # 检查是否连上AP的最大时长； 1=1秒， 2=2秒....
connect_net=30    # 检查是否联网时最大时长；1=3秒，2=6秒.... (信号差建议设置成50)
sig=10             # 跳过信号低于sig的AP

# 【自动切换中继信号】功能 填写配置参数启动
cat >/tmp/ap2g5g.txt <<-\EOF
# 中继AP配置填写说明：
# 各参数用【@】分割开，如果有多个信号可回车换行继续填写即可(从第一行的参数开始搜寻)【第一行的是最优先信号】
# 搜寻时无线网络会瞬断一下
# 参数说明：
# ①2.4Ghz或5Ghz："2"=【2.4Ghz】"5"=【5Ghz】
# ②无线AP工作模式："0"=【AP（桥接被禁用）】"1"=【WDS桥接（AP被禁用）】"2"=【WDS中继（网桥 + AP）】"3"=【AP-Client（AP被禁用）】"4"=【AP-Client + AP】
# ③无线AP-Client角色： "0"=【LAN bridge】"1"=【WAN (Wireless ISP)】
# ④中继AP 的 SSID："ASUS"
# ⑤中继AP 密码："1234567890"
# ⑥中继AP 的 MAC地址："20:76:90:20:B0:F0"【可以不填，不限大小写】
# 下面是信号填写参考例子：（删除前面的注释#可生效）
#2@4@1@ASUS@1234567890
#2@4@1@ASUS_中文@1234567890@34:bd:f9:1f:d2:b1
#2@4@1@ASUS3@1234567890@34:bd:f9:1f:d2:b0




# *此脚本存在非注释字符时，即生效* #
EOF
cat /tmp/ap2g5g.txt | grep -v '^#'  | grep -v "^$" > /tmp/ap2g5g
killall sh_apauto.sh
if [ -s /tmp/ap2g5g ] ; then
cat >/tmp/sh_apauto.sh <<-\EOF
#!/bin/sh
    logger -t "【AP中继】" "连接守护启动"
    while true; do
        if [ ! -f /tmp/apc.lock ] ; then
            if [[ $(cat /tmp/apauto.lock) == 1 ]] ; then
            #【1】 当中继信号断开时启动自动搜寻
                a2=`iwconfig apcli0 | awk -F'"' '/ESSID/ {print $2}'`
                a5=`iwconfig apclii0 | awk -F'"' '/ESSID/ {print $2}'`
                [ "$a2" = "" -a "$a5" = "" ] && ap=1 || ap=0
                if [ "$ap" = "1" ] ; then
                    logger -t "【AP中继】" "连接中断，启动自动搜寻"
                    /etc/storage/inet_state_script.sh 0 t &
                fi
            fi
            if [[ $(cat /tmp/apauto.lock) == 0 ]] ; then
            #【2】 Internet互联网断线后自动搜寻
            ping_text=`ping -4 223.5.5.5 -c 1 -w 4 -q`
            ping_time=`echo $ping_text | awk -F '/' '{print $4}'| awk -F '.' '{print $1}'`
            ping_loss=`echo $ping_text | awk -F ', ' '{print $3}' | awk '{print $1}'`
            if [ ! -z "$ping_time" ] ; then
                echo "ping：$ping_time ms 丢包率：$ping_loss"
             else
                echo "ping：失效"
            fi
            if [ ! -z "$ping_time" ] ; then
            echo "online"
            else
                echo "Internet互联网断线后自动搜寻"
                    /etc/storage/inet_state_script.sh 0 t &
                fi
            fi
        fi
        sleep 69
    done
EOF
    chmod 777 "/tmp/sh_apauto.sh"
    echo $apauto > /tmp/apauto.lock
    [ "$1" = "crontabs" ] && /tmp/sh_apauto.sh &
else
    echo "" > /tmp/apauto.lock
fi


EOF
		chmod 755 "$script_aps"
	fi

	# create vpn server action script
	if [ ! -f "$script_vpnsc" ] ; then
		cat > "$script_vpnsc" <<EOF
#!/bin/sh

### Custom user script
### Called after remote peer connected/disconnected to internal VPN server
### \$1 - peer action (up/down)
### \$2 - peer interface name (e.g. ppp10)
### \$3 - peer local IP address
### \$4 - peer remote IP address
### \$5 - peer name

peer_if="\$2"
peer_ip="\$4"
peer_name="\$5"

### example: add static route to private LAN subnet behind a remote peer

func_ipup()
{
#  if [ "\$peer_name" == "dmitry" ] ; then
#    route add -net 192.168.5.0 netmask 255.255.255.0 dev \$peer_if
#  elif [ "\$peer_name" == "victoria" ] ; then
#    route add -net 192.168.8.0 netmask 255.255.255.0 dev \$peer_if
#  fi
   return 0
}

func_ipdown()
{
#  if [ "\$peer_name" == "dmitry" ] ; then
#    route del -net 192.168.5.0 netmask 255.255.255.0 dev \$peer_if
#  elif [ "\$peer_name" == "victoria" ] ; then
#    route del -net 192.168.8.0 netmask 255.255.255.0 dev \$peer_if
#  fi
   return 0
}

case "\$1" in
up)
  func_ipup
  ;;
down)
  func_ipdown
  ;;
esac

EOF
		chmod 755 "$script_vpnsc"
	fi

	# create vpn client action script
	if [ ! -f "$script_vpncs" ] ; then
		cat > "$script_vpncs" <<EOF
#!/bin/sh

### Custom user script
### Called after internal VPN client connected/disconnected to remote VPN server
### \$1        - action (up/down)
### \$IFNAME   - tunnel interface name (e.g. ppp5 or tun0)
### \$IPLOCAL  - tunnel local IP address
### \$IPREMOTE - tunnel remote IP address
### \$DNS1     - peer DNS1
### \$DNS2     - peer DNS2

# private LAN subnet behind a remote server (example)
peer_lan="192.168.9.0"
peer_msk="255.255.255.0"

### example: add static route to private LAN subnet behind a remote server

func_ipup()
{
#  route add -net \$peer_lan netmask \$peer_msk gw \$IPREMOTE dev \$IFNAME
   return 0
}

func_ipdown()
{
#  route del -net \$peer_lan netmask \$peer_msk gw \$IPREMOTE dev \$IFNAME
   return 0
}

logger -t vpnc-script "\$IFNAME \$1"

case "\$1" in
up)
  func_ipup
  ;;
down)
  func_ipdown
  ;;
esac

EOF
		chmod 755 "$script_vpncs"
	fi

	# create Ez-Buttons script
	if [ ! -f "$script_ezbtn" ] ; then
		cat > "$script_ezbtn" <<EOF
#!/bin/sh

### Custom user script
### Called on WPS or FN button pressed
### \$1 - button param

[ -x /opt/bin/on_wps.sh ] && /opt/bin/on_wps.sh \$1 &

EOF
		chmod 755 "$script_ezbtn"
	fi

	# create user dnsmasq.conf
	[ ! -d "$dir_dnsmasq" ] && mkdir -p -m 755 "$dir_dnsmasq"
	for i in dnsmasq.conf hosts ; do
		[ -f "$dir_storage/$i" ] && mv -n "$dir_storage/$i" "$dir_dnsmasq"
	done
	if [ ! -f "$user_dnsmasq_conf" ] ; then
		cat > "$user_dnsmasq_conf" <<EOF
# Custom user conf file for dnsmasq
# Please add needed params only!

### Web Proxy Automatic Discovery (WPAD)
dhcp-option=252,"\n"

### Set the limit on DHCP leases, the default is 150
#dhcp-lease-max=150

### Add local-only domains, queries are answered from hosts or DHCP only
#local=/router/localdomain/

### Examples:

### Enable built-in TFTP server
#enable-tftp

### Set the root directory for files available via TFTP.
#tftp-root=/opt/srv/tftp

### Make the TFTP server more secure
#tftp-secure

### Set the boot filename for netboot/PXE
#dhcp-boot=pxelinux.0

### Log for all queries
#log-queries

### Keep DHCP host name valid at any times
#dhcp-to-host

EOF
	if [ -f /usr/bin/vlmcsd ]; then
		cat >> "$user_dnsmasq_conf" <<EOF
### vlmcsd related
srv-host=_vlmcs._tcp,my.router,1688,0,100

EOF
	fi

	if [ -f /usr/bin/wing ]; then
		cat >> "$user_dnsmasq_conf" <<EOF
# Custom domains to gfwlist
#gfwlist=mit.edu
#gfwlist=openwrt.org,lede-project.org
#gfwlist=github.com,github.io,githubusercontent.com

EOF
	fi

	if [ -d $dir_gfwlist ]; then
		cat >> "$user_dnsmasq_conf" <<EOF
### gfwlist related (resolve by port 5353)
#min-cache-ttl=3600
#conf-dir=/etc/storage/gfwlist

EOF
	fi
		chmod 644 "$user_dnsmasq_conf"
	fi

	# create user dns servers
	if [ ! -f "$user_dhcp_conf" ] ; then
		cat > "$user_dhcp_conf" <<EOF
#6C:96:CF:E0:95:55,192.168.1.10,iMac

EOF
		chmod 644 "$user_dhcp_conf"
	fi

	# create user inadyn.conf"
	[ ! -d "$dir_inadyn" ] && mkdir -p -m 755 "$dir_inadyn"
	if [ ! -f "$user_inadyn_conf" ] ; then
		cat > "$user_inadyn_conf" <<EOF
# Custom user conf file for inadyn DDNS client
# Please add only new custom system!

### Example for twoDNS.de:

#system custom@http_srv_basic_auth
#  ssl
#  checkip-url checkip.two-dns.de /
#  server-name update.twodns.de
#  server-url /update\?hostname=
#  username account
#  password secret
#  alias example.dd-dns.de

EOF
		chmod 644 "$user_inadyn_conf"
	fi

	# create user hosts
	if [ ! -f "$user_hosts" ] ; then
		cat > "$user_hosts" <<EOF
# Custom user hosts file
# Example:
# 192.168.1.100		Boo

EOF
		chmod 644 "$user_hosts"
	fi

	# create user AP confs
	[ ! -d "$dir_wlan" ] && mkdir -p -m 755 "$dir_wlan"
	if [ ! -f "$dir_wlan/AP.dat" ] ; then
		cat > "$dir_wlan/AP.dat" <<EOF
# Custom user AP conf file

EOF
		chmod 644 "$dir_wlan/AP.dat"
	fi

	if [ ! -f "$dir_wlan/AP_5G.dat" ] ; then
		cat > "$dir_wlan/AP_5G.dat" <<EOF
# Custom user AP conf file

EOF
		chmod 644 "$dir_wlan/AP_5G.dat"
	fi

	# create openvpn files
	if [ -x /usr/sbin/openvpn ] ; then
		[ ! -d "$dir_ovpncli" ] && mkdir -p -m 700 "$dir_ovpncli"
		[ ! -d "$dir_ovpnsvr" ] && mkdir -p -m 700 "$dir_ovpnsvr"
		dir_ovpn="$dir_storage/openvpn"
		for i in ca.crt dh1024.pem server.crt server.key server.conf ta.key ; do
			[ -f "$dir_ovpn/$i" ] && mv -n "$dir_ovpn/$i" "$dir_ovpnsvr"
		done
		if [ ! -f "$user_ovpnsvr_conf" ] ; then
			cat > "$user_ovpnsvr_conf" <<EOF
# Custom user conf file for OpenVPN server
# Please add needed params only!

### Max clients limit
max-clients 10

### Internally route client-to-client traffic
client-to-client

### Allow clients with duplicate "Common Name"
;duplicate-cn

### Legacy LZO adaptive compression
;comp-lzo adaptive
;push "comp-lzo adaptive"

### Keepalive and timeout
keepalive 10 60

### Process priority level (0..19)
nice 3

### Syslog verbose level
verb 0
mute 10

EOF
			chmod 644 "$user_ovpnsvr_conf"
		fi

		if [ ! -f "$user_ovpncli_conf" ] ; then
			cat > "$user_ovpncli_conf" <<EOF
# Custom user conf file for OpenVPN client
# Please add needed params only!

### If your server certificates with the nsCertType field set to "server"
ns-cert-type server

### Process priority level (0..19)
nice 0

### Syslog verbose level
verb 0
mute 10

EOF
			chmod 644 "$user_ovpncli_conf"
		fi
	fi

	# create strongswan files
	if [ -x /usr/sbin/ipsec ] ; then
		[ ! -d "$dir_sswan" ] && mkdir -p -m 700 "$dir_sswan"
		[ ! -d "$dir_sswan_crt" ] && mkdir -p -m 700 "$dir_sswan_crt"
		[ ! -d "$dir_sswan_crt/cacerts" ] && mkdir -p -m 700 "$dir_sswan_crt/cacerts"
		[ ! -d "$dir_sswan_crt/certs" ] && mkdir -p -m 700 "$dir_sswan_crt/certs"
		[ ! -d "$dir_sswan_crt/private" ] && mkdir -p -m 700 "$dir_sswan_crt/private"

		if [ ! -f "$user_sswan_conf" ] ; then
			cat > "$user_sswan_conf" <<EOF
### strongswan.conf - user strongswan configuration file

EOF
			chmod 644 "$user_sswan_conf"
		fi
		if [ ! -f "$user_sswan_ipsec_conf" ] ; then
			cat > "$user_sswan_ipsec_conf" <<EOF
### ipsec.conf - user strongswan IPsec configuration file

EOF
			chmod 644 "$user_sswan_ipsec_conf"
		fi
		if [ ! -f "$user_sswan_secrets" ] ; then
			cat > "$user_sswan_secrets" <<EOF
### ipsec.secrets - user strongswan IPsec secrets file

EOF
			chmod 644 "$user_sswan_secrets"
		fi
	fi
}

case "$1" in
load)
	func_get_mtd
	func_mdir
	func_load
	;;
save)
	[ -f "$slk" ] && exit 1
	func_get_mtd
	func_mdir
	func_tarb
	func_save
	;;
backup)
	func_mdir
	func_tarb
	func_backup
	;;
restore)
	func_get_mtd
	func_restore
	;;
erase)
	func_get_mtd
	func_erase
	;;
reset)
	func_stop_apps
	func_reset
	func_fill
	func_start_apps
	;;
fill)
	func_mdir
	func_fill
	;;
*)
	echo "Usage: $0 {load|save|backup|restore|erase|reset|fill}"
	exit 1
	;;
esac

exit $result
