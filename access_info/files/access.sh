#! /bin/bash
###################################################
# Host Summary Generator
#
# Description: Generate host summary quickly and easily
# Contact: Alan.sun@chinanetcloud.com
# Version:
###################################################
# Changes:
#   2010-05-25    AS    Initial creation
#   2010-12-27    CH    Fix count memory bug
#   2012-04-01    AS    Detect Public IP / Other fixes
###################################################


# Check root
if [ $EUID -ne 0 ]; then
  echo "    ERROR:This script can only be run by root!"
  exit 1
fi

# Check OS
if [ ! -f /etc/redhat-release ];then
  echo "    ERROR:This script is for CentOS/RHEL only!"
  exit 1
fi

name_val() {
    printf "%20s | %s\n" "$1" "$(echo $2)"
}

# Get IP info.IP address got from ifconfig doesn't always works.
clear
echo "--------------------------------------------------------------------------"
echo "Network Interface Configuration for $HOSTNAME:"
ifconfig -a | sed -n '/^[^ \t]/{N;s/\(^[^ ]*\).*addr:\([^ ]*\).*/\1\t\2/p}'|grep -v lo
OUT_IP=$(wget -O - -q --timeout=8 --user-agent='Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 2.0.50727; InfoPath.1; .NET CLR 1.1.4322)' http://www.mon-ip.com | awk '/Ip =/ {print $NF}')

if [ -n "$OUT_IP" ]; then
    echo "Extra IP information: $OUT_IP"
fi

#echo "--------------------------------------------------------------------------"

#while true; do
#    read -p  "Please input the PUBLIC IP for SSH connection : " SSH_IP
    # simple ip check
#    if [[ $SSH_IP =~ ^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$ ]]; then
#        break
#    else
#        echo "[ERROR]: Invalid IP address,please try again !"
#    fi
#done
#read -p  "Please input the PORT for SSH connection(default 40022) : " SSH_PORT
#if [ -z "$SSH_PORT" ]; then
#    SSH_PORT=40022
#fi
#clear

# Get SSH User and Port
SSH_USER=$(echo $(grep sshers /etc/group | awk -F: '{print $NF}'|sed  's/,/\n/g'| grep -Ev '^nc|^root'))

basic_info() {
    echo
    echo "---------------------------  HOST SUMMARY FOR $(echo "$HOSTNAME" | awk '{print toupper($0)}')  --------------------------- "
    echo "  Hostname: $HOSTNAME"
#    echo "  SSH IP: $SSH_IP"
    echo "  SSH USER: $SSH_USER"
#    echo "  SSH PORT: $SSH_PORT"
#    echo "  SSH Command: ssh -p $SSH_PORT SSH_USER@$SSH_IP"
    echo "  System User: $SYSTEM_USER"
    echo "  IP Address: "
    ifconfig -a | sed -n '/^[^ \t]/{N;s/\(^[^ ]*\).*addr:\([^ ]*\).*/\1\t\2/p}'|grep -v lo
    echo "Extra IP information: $OUT_IP"
    # Get System Users info
    SYSTEM_USER=$(echo $(awk -F: '{if($3>499 && $3<2000 ) print $1}' /etc/passwd | tr ' ' '\n'| grep -Ev '^(nc|zabbix|jboss)'))
    echo
}

# Get software version info
parse_software() {
    echo "Applications:"
    if which java &>/dev/null ; then
        BIN_JAVA=$(which java)
        VERSION_JAVA=$(java -version 2>&1|head -n 1|awk -F'"' '{print $2}')
        name_val "Java Version" "$VERSION_JAVA"
    fi

    if which perl &>/dev/null ; then
        BIN_PERL=$(which perl)
        VERSION_PERL=$(perl -V|perl -ne 'if (/.*revision (\d+) version (\d+) subversion (\d+)/) {print "$1.$2.$3\n"}')
        name_val "Perl Version" "$VERSION_PERL"
    fi

    if which python &>/dev/null ; then
        BIN_PYTHON=$(which python)
        VERSION_PYTHON=$(python -V 2>&1 | awk '{print $2}')
        name_val "Python Version" "$VERSION_PYTHON"
    fi

    if which httpd &>/dev/null ; then
        BIN_APACHE=$(which httpd)
        VERSION_APACHE=$(httpd -v| head -n 1|perl -pi -e 's/.*(\d+\.\d+.\d+).*/$1/')
        name_val "Apache Version" "$VERSION_APACHE"
    fi

    if which nginx &>/dev/null ; then
        BIN_NGINX=$(which nginx)
        VERSION_NGINX=$(nginx -v 2>&1 | perl -pi -e 's/.*(\d+\.\d+.\d+).*/$1/')
        name_val "Nginx Version" "$VERSION_NGINX"
    fi

    if which lighttpd &>/dev/null ; then
        BIN_LIGHTTPD=$(which lighttpd)
        VERSION_LIGHTTPD=$(lighttpd -v| head -n 1| perl -pi -e 's/.*(\d+\.\d+.\d+).*/$1/')
        name_val "Lighttpd Version" "$VERSION_LIGHTTPD"
    fi

    if which php &>/dev/null ; then
        BIN_PHP=$(which php)
        VERSION_PHP=$(php -v 2>/dev/null | head -n 1 | perl -pi -e 's/.*(\d+\.\d+.\d+).*/$1/')
        name_val "PHP Version" "$VERSION_PHP"
    fi

    if which memcached &>/dev/null ; then
        BIN_MEMCACHED=$(which memcached)
        VERSION_MEMCACHED=$(memcached -h|head -n 1|awk '{print $2}')
        name_val "Memcached Version" "$VERSION_MEMCACHED"
    fi

    if [ -n "$CATALINA_HOME" ]; then
        VERSION_TOMCAT=$($CATALINA_HOME/bin/version.sh 2>/dev/null | awk -F: '/version/ {print $2}')
        name_val "Tomcat Version" "$VERSION_TOMCAT"
    fi

    if which mysql &>/dev/null ; then
        BIN_MYSQL_CLIENT=$(which mysql)
        VERSION_MYSQL_CLIENT=$(mysql -V | perl -pi -e 's/.*(\d+\.\d+.\d+).*/$1/')
        name_val "MySQL Client Version" "$VERSION_MYSQL_CLIENT"
    fi

    if which mongod &>/dev/null; then
        VERSION_MONGOD=$(/usr/bin/mongod --version|awk -F"(,| )" '/db version/ {print substr($3,2)}')
        BIN_MONGOD=$(which mongod)
        name_val "MongoDB Version" "$VERSION_MONGOD"
    fi

    if which psql &>/dev/null ; then
        BIN_PSQL=$(which psql)
        VERSION_PSQL=$(psql -V | head -n 1 | perl -pi -e 's/.*(\d+\.\d+.\d+).*/$1/')
        name_val "PostgreSQL Version" "$VERSION_PSQL"
    fi
}


# MySQL information
mysql_info() {
    MYSQL_SERVER_VERSION=$(rpm -qa|grep -i mysql-server|perl -ne 'if($_=~/.*-(\d+\.\d+.\d+)-.*/) {print "$1"}')
    if [ -n "$MYSQL_SERVER_VERSION" ]; then
      name_val "MySQL Server Version" "$MYSQL_SERVER_VERSION"
      MYSQL_DATA=`ps aux | awk '{if($1~/mysql/) print $13}' | sed 's/datadir=/Datadir: /'`
      if [ -n "$MYSQL_DATA" ];then
          echo "    $MYSQL_DATA"
          # Get MySQL Users
          echo -n "    Getting database users,please provide password for MySQL root:"
          read -s dbpassword
          echo
              if [ -z $dbpassword ]; then
                  MYSQL_USER=`mysql -N -e "use mysql;select User from user where user<>''"  2>/dev/null | sort | uniq | grep -Ev "ncbackupdb|root|nccheckdb|ncdba|repl" | tr "\n" ","`
              else
                  MYSQL_USER=`mysql -N -uroot -p$dbpassword -e "use mysql;select User from user where user<>''"  2>/dev/null | sort | uniq | grep -Ev "ncbackupdb|root|nccheckdb|ncdba|repl" | tr "\n" " "`
              fi

              if [ -z "$MYSQL_USER" ]; then
                echo "    ERROR: Database Access Denied!"
              else
                echo "    --DB Users: $MYSQL_USER"
          fi
      fi
    fi
}



cpu_info() {
    echo "CPU/MEM/DISK "
    # Get CPU info
    CPU_NUM=`grep "\<processor\>" /proc/cpuinfo | wc -l`
    CPU_MODEL=`awk -F: '{if($0~/model name/) print $2}' /proc/cpuinfo | uniq `
    echo "  CPU: "$CPU_NUM" x "$CPU_MODEL""
}

# Get RAM/SWAP info
memory_info() {
    RAM=$(free -m | grep Mem | awk '{print $2}')
    echo "  RAM: $RAM MB"

    SWAP=$(free -m|awk '{if($1~/Swap/)print $2}')
    echo "  SWAP: $SWAP MB"
}

# Get Disk info
disk_info() {
    DISK_TOTAL=$(echo "scale=1;$(fdisk -l  2>/dev/null | awk '{if($0~/Disk.*[shx]*d[a-z]/) print $(NF-1)}' | awk 'BEGIN{OFMT="%.1f"} {total+=$1}END{print total/1024/1024/1024}')" | bc)
    echo "  DISK: $DISK_TOTAL GB"

    # Get VG/LV info
    echo "Disk Layout:"
    echo "  Physical Disk: "
    fdisk -l  2>/dev/null | awk '{if($0~/Disk.*[sh]d[a-z]/) print "        "$2,$(NF-1)/1024/1024/1024" GB"}'

    echo "  Volume Group Info:"
    vgs 2>/dev/null | sed '1d' | awk '{print "        "$1" : "$6}'

    echo "  Logical Volume Info:"
    for lv in $(lvdisplay  2>/dev/null | grep "LV Name" | awk '{print $3}')
    do
      echo -n "        "
      MOUNT_POINT=`grep "$lv" /etc/fstab | awk '{print $2" : "}'`
      if [ -z "$MOUNT_POINT" ];then
          echo -ne "No Mount Point : "
      else
          echo -ne "$MOUNT_POINT"
      fi
      echo -n "$lv"
      LV_SIZE=`lvdisplay "$lv"  2>/dev/null | awk '{if($0~/Size/) print $3" "$4}'`
      echo "  $LV_SIZE "
    done
    echo
}

iptables_info() {
    # Get Iptables info
    echo "Iptables:"
    echo -n "    - INPUT  :"
    for PORT_IN in `iptables -nvL INPUT | awk -F: '{if ($0~/tcp spt/) print$NF}' | uniq | sort -n`; do
        SERVICE=$(grep "\<$PORT_IN/tcp\>" /etc/services | awk '{print $1}')
        if [ -z "$SERVICE" ]; then
            case "$PORT_IN" in
                11211) SERVICE="memcached" ;;
                10050) SERVICE="zabbix-agent" ;;
                40022|40024|60022) SERVICE="ssh" ;;
                *) SERVICE="" ;;
            esac
        fi
        echo -n "$SERVICE($PORT_IN) - "
    done
    echo
    echo
}

basic_info > /tmp/access_info.txt
cpu_info >> /tmp/access_info.txt
memory_info >> /tmp/access_info.txt
disk_info >> /tmp/access_info.txt
iptables_info >> /tmp/access_info.txt
parse_software >> /tmp/access_info.txt
mysql_info >> /tmp/access_info.txt


### Binary Definition ###
MAIL=/bin/mail
EMAIL_ADDRESS1=pm_auto_notify@chinanetcloud.com
#EMAIL_ADDRESS1=jason.you@chinanetcloud.com
EMAIL_ADDRESS2=
EMAIL_ADDRESS3=
EMAIL_ADDRESS4=
EMAIL_ADDRESS5=
EMAIL_ADDRESS6=

DATE=$(date "+%Y%m%d")
ACCESS_REPORT=/tmp/access_info.txt
HOSTNAME=$(hostname)

# Send email
echo "Please check the attachment" | $MAIL -s "Access Report on $HOSTNAME - $DATE " $EMAIL_ADDRESS1 -c $EMAIL_ADDRESS2,$EMAIL_ADDRESS5,$EMAIL_ADDRESS6 < $ACCESS_REPORT

exit 0
