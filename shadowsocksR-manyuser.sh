#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#=================================================================#
#   System Required:  CentOS 6,7, Debian, Ubuntu                  #
#   Description: One click Install ShadowsocksR Server            #
#   Author: Teddysun <i@teddysun.com>                             #
#   Thanks: @breakwa11 <https://twitter.com/breakwa11>            #
#   Intro:  https://shadowsocks.be/9.html                         #
#   Modifier: @Dwwwwww <https://github.com/dwwwwww>               #
#=================================================================#
echo "#############################################################"
echo "# One click Install ShadowsocksR Server for ss-panel v2     #"
echo "# Intro: https://shadowsocks.be/9.html                      #"
echo "# Author: Teddysun <i@teddysun.com>                         #"
echo "# Thanks: @breakwa11 <https://twitter.com/breakwa11>        #"
echo "# Modifier: @Dwwwwww <https://github.com/dwwwwww>           #"
echo "#############################################################"
#Current folder
cur_dir=`pwd`
# Get public IP address
IP=$(ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
if [[ "$IP" = "" ]]; then
    IP=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
fi

# Make sure only root can run our script
function rootness(){
    if [[ $EUID -ne 0 ]]; then
       echo "Error:This script must be run as root!" 1>&2
       exit 1
    fi
}

# Check OS
function checkos(){
    if [ -f /etc/redhat-release ];then
        OS='CentOS'
    elif [ ! -z "`cat /etc/issue | grep bian`" ];then
        OS='Debian'
    elif [ ! -z "`cat /etc/issue | grep Ubuntu`" ];then
        OS='Ubuntu'
    else
        echo "Not support OS, Please reinstall OS and retry!"
        exit 1
    fi
}

# Get version
function getversion(){
    if [[ -s /etc/redhat-release ]];then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else    
        grep -oE  "[0-9.]+" /etc/issue
    fi    
}

# CentOS version
function centosversion(){
    local code=$1
    local version="`getversion`"
    local main_ver=${version%%.*}
    if [ $main_ver == $code ];then
        return 0
    else
        return 1
    fi        
}

# Disable selinux
function disable_selinux(){
if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
fi
}

#Config ShadowsocksR
function pre_install(){
    # Not support CentOS 5
    if centosversion 5; then
        echo "Not support CentOS 5, please change OS to CentOS 6+/Debian 7+/Ubuntu 12+ and retry."
        exit 1
    fi
    # Set ShadowsocksR MySQL host
    echo "Please input MySQL host for ShadowsocksR:"
    read -p "(Default host: localost):" dbhost
    [ -z "$dbhost" ] && dbhost="localost"
    echo
    echo "---------------------------"
    echo "MySQL host = $dbhost"
    echo "---------------------------"
    echo
    # Set ShadowsocksR MySQL port
    echo -e "Please input MySQL port for ShadowsocksR:"
    read -p "(Default port: 3306):" dbport
    [ -z "$dbport" ] && dbport="3306"
    expr $dbport + 0 &>/dev/null
    if [ $? -eq 0 ]; then
        if [ $dbport -ge 1 ] && [ $dbport -le 65535 ]; then
            echo
            echo "---------------------------"
            echo "MySQL port = $dbport"
            echo "---------------------------"
            echo
        else
            echo "Input error! Please input correct number."
			exit 1
        fi
    else
        echo "Input error! Please input correct number."
		exit 1
    fi
	# Set ShadowsocksR MySQL user
    echo -e "Please input MySQL user for ShadowsocksR:"
    read -p "(Default user: root):" dbuser
    [ -z "$dbuser" ] && dbuser="root"
            echo
            echo "---------------------------"
            echo "MySQL user = $dbuser"
            echo "---------------------------"
            echo
    # Set ShadowsocksR MySQL password
    echo -e "Please input MySQL password for ShadowsocksR:"
    read -p "(Default password: pass):" dbpassword
    [ -z "$dbpassword" ] && dbpassword="pass"
            echo
            echo "---------------------------"
            echo "MySQL password = $dbpassword"
            echo "---------------------------"
            echo
    # Set ShadowsocksR MySQL Db
    echo -e "Please input MySQL Db for ShadowsocksR:"
    read -p "(Default Db: sspanel):" db
    [ -z "$db" ] && db="sspanel"
            echo
            echo "---------------------------"
            echo "MySQL Db = $db"
            echo "---------------------------"
            echo
   # Set ShadowsocksR Method
    echo -e "Please input Method for ShadowsocksR:"
    read -p "(Default method: aes-256-cfb):" method
    [ -z "$method" ] && method="aes-256-cfb"
            echo
            echo "---------------------------"
            echo "Method = $method"
            echo "---------------------------"
            echo

    # Set ShadowsocksR Protocol
    echo -e "Please input Protocol for ShadowsocksR:"
    read -p "(Default Protocol: auth_sha1_v4_compatible):" protocol
    [ -z "$protocol" ] && protocol="auth_sha1_v4_compatible"
            echo
            echo "---------------------------"
            echo "Protocol = $protocol"
            echo "---------------------------"
            echo
	# Set ShadowsocksR Obfs
    echo -e "Please input Obfs for ShadowsocksR:"
    read -p "(Default obfs: http_post_compatible):" obfs
    [ -z "$obfs" ] && obfs="http_post_compatible"
            echo
            echo "---------------------------"
            echo "Obfs = $obfs"
            echo "---------------------------"
            echo	
	# Set ShadowsocksR Directory
    echo -e "Please input a Directory for ShadowsocksR (Without the last /) :"
    read -p "(Default directory: /usr/local/shadowsocks):" directory
    [ -z "$directory" ] && directory="/usr/local/shadowsocks"
            echo
            echo "---------------------------"
            echo "Directory = $directory"
            echo "---------------------------"
            echo	
}

# Download files
function download_files(){
    # Download libsodium file
    #if ! wget --no-check-certificate -O libsodium-1.0.11.tar.gz https://github.com/jedisct1/libsodium/releases/download/1.0.11/libsodium-1.0.11.tar.gz; then
        #echo "Failed to download libsodium file!"
        #exit 1
    #fi
    # Download ShadowsocksR chkconfig file
    if [ "$OS" == 'CentOS' ]; then
        if ! wget --no-check-certificate https://raw.githubusercontent.com/Dwwwwww/shadowsocks_install/master/shadowsocksR-manyuser -O /etc/init.d/shadowsocks; then
            echo "Failed to download ShadowsocksR chkconfig file!"
            exit 1
        fi
    else
        if ! wget --no-check-certificate https://github.com/Dwwwwww/shadowsocks_install/raw/master/shadowsocksR-manyuser-debian -O /etc/init.d/shadowsocks; then
            echo "Failed to download ShadowsocksR chkconfig file!"
            exit 1
        fi
    fi
}

# firewall set
function firewall_set(){
    echo "firewall set start..."
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    echo "firewall set completed..."
}

# Install ShadowsocksR
function install_ss(){

	# Install necessary dependencies
	if [ "$OS" == 'CentOS' ]; then
        yum install -y wget unzip git openssl-devel gcc swig python python-devel python-setuptools autoconf libtool libevent ntpdate
        yum install -y m2crypto automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel
		easy_install pip
    else
        apt-get -y update
        apt-get -y install python python-dev python-pip python-setuptools python-m2crypto curl wget git unzip gcc swig automake make perl cpio build-essential ntpdate
    fi
	pip install cymysql
    # Install libsodium
    #tar zxf libsodium-1.0.11.tar.gz
    #cd $cur_dir/libsodium-1.0.11
    #./configure && make && make install
    echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf
    ldconfig
    # Install & Config ShadowsocksR
    git clone -b manyuser https://github.com/breakwa11/shadowsocks.git "${directory}"
	cd /usr/local/shadowsocks
	cp apiconfig.py userapiconfig.py
	cp mysql.json usermysql.json
	cp config.json user-config.json
    cat > /usr/local/shadowsocks/usermysql.json<<-EOF
{
    "host": "${dbhost}",
    "port": ${dbport},
    "user": "${dbuser}",
    "password": "${dbpassword}",
    "db": "${db}",
    "node_id": 0,
    "transfer_mul": 1.0,
    "ssl_enable": 0,
    "ssl_ca": "",
    "ssl_cert": "",
    "ssl_key": ""
}
EOF
	sed -i -e "s|aes-256-cfb|${method}|" user-config.json
	sed -i -e "s|auth_sha1_v4_compatible|${protocol}|" user-config.json
	sed -i -e "s|tls1.2_ticket_auth_compatible|${obfs}|" user-config.json
	sed -i -e 's|"connect_verbose_info": 0|"connect_verbose_info": 1|' user-config.json
	sed -i -e "s|/usr/local/shadowsocks|${directory}|" /etc/init.d/shadowsocks
    if [ -f /usr/local/shadowsocks/server.py ]; then
        chmod +x /etc/init.d/shadowsocks
        # Add run on system start up
        if [ "$OS" == 'CentOS' ]; then
            chkconfig --add shadowsocks
            chkconfig shadowsocks on
        else
            update-rc.d -f shadowsocks defaults
        fi
        # Run ShadowsocksR in the background
        /etc/init.d/shadowsocks start
        clear
        echo
        echo "Congratulations, ShadowsocksR install completed!"
        echo -e "Server IP: \033[41;37m ${IP} \033[0m"
        echo -e "MySQL Host: \033[41;37m ${dbhost} \033[0m"
        echo -e "MySQL Port: \033[41;37m ${dbport} \033[0m"
        echo -e "MySQL User: \033[41;37m ${dbuser} \033[0m"
        echo -e "MySQL Password: \033[41;37m ${dbpassword} \033[0m"
        echo -e "MySQL Db: \033[41;37m ${db} \033[0m"
        echo -e "Method: \033[41;37m ${method} \033[0m"
        echo -e "Protocol: \033[41;37m ${protocol} \033[0m"
        echo -e "Obfs: \033[41;37m ${obfs} \033[0m"
        echo
        echo "Welcome to visit:https://shadowsocks.be/9.html"
        echo "If you want to change protocol & obfs, reference URL:"
        echo "https://github.com/breakwa11/shadowsocks-rss/wiki/Server-Setup"
        echo
        echo "Enjoy it!"
        echo
		chmod +x /usr/local/shadowsocks/*.sh
    else
        echo "Shadowsocks install failed! Unknown Error."
        install_cleanup
        exit 1
    fi
}

# Change timezone
function check_datetime(){
 rm -rf /etc/localtime
 ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
 ntpdate 1.cn.pool.ntp.org
 }
 
# Install cleanup
function install_cleanup(){
    cd $cur_dir
    rm -f libsodium-1.0.11.tar.gz
    rm -rf libsodium-1.0.11
}


# Uninstall ShadowsocksR
function uninstall_shadowsocks(){
    printf "Are you sure uninstall ShadowsocksR? (y/n) "
    printf "\n"
    read -p "(Default: n):" answer
    if [ -z $answer ]; then
        answer="n"
    fi
    if [ "$answer" = "y" ]; then
        /etc/init.d/shadowsocks status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            /etc/init.d/shadowsocks stop
        fi
        checkos
        if [ "$OS" == 'CentOS' ]; then
            chkconfig --del shadowsocks
        else
            update-rc.d -f shadowsocks remove
        fi
        rm -f /etc/init.d/shadowsocks
        rm -rf /usr/local/shadowsocks
        echo "ShadowsocksR uninstall success!"
    else
        echo "uninstall cancelled, Nothing to do"
    fi
}

# Install ShadowsocksR
function install_shadowsocks(){
    checkos
    rootness
    pre_install
    disable_selinux
    download_files
    install_ss
   firewall_set
   check_datetime
    install_cleanup
}

# Initialization step
action=$1
[ -z $1 ] && action=install
case "$action" in
install)
    install_shadowsocks
    ;;
uninstall)
    uninstall_shadowsocks
    ;;
*)
    echo "Arguments error! [${action} ]"
    echo "Usage: `basename $0` {install|uninstall}"
    ;;
esac