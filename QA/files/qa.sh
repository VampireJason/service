#!/bin/bash
################################################
# nc_qa.sh
#
# Description:
# - check software instalation
# - check basic system integrity
################################################
# CHANGELOG
# Feb 01, 2012  AL: * Initial Create
# Apr 25, 2012  AL: * Bugfixes, format changes, better logging

#RED="\033[0;31m"
#GREEN="\033[0;32m"
#NO_COLOR="\033[0m"

ERROR_LOG=/tmp/qa/qa_error.log
INSTALL_LOG=/tmp/qa/install.log
MOUNT_LOG=/tmp/qa/mount.log
INFORMATION_LOG=/tmp/qa/information.log
MYSQL_LOG=/tmp/qa/mysql.log

rm -rf /tmp/qa 2> /dev/null
mkdir -p /tmp/qa
touch $ERROR_LOG
touch $INSTALL_LOG
touch $INFORMATION_LOG

check_mysql() {
  mysql_rpm_check=`yum list installed | grep -iE ^MySQL-server | wc -l`
  if [ $mysql_rpm_check -ne 0 ] ; then
    echo " - MySQL "
    echo -en "$GREEN  Checking mount point: "
    mysql_check_mount=`df -hP| grep -i mysql`
    if [ $? -ne 0 ]; then
      echo -e "$RED /var/lib/mysql is not mounted. "
      echo " - MYSQL: /var/lib/mysql is not mounted." >> $ERROR_LOG
    else
      echo -e " $mysql_check_mount"  >> $MOUNT_LOG
      echo -e " $mysql_check_mount"
    fi

    echo -en "  Checking /etc/fstab entry: "
    mysql_fstab=`grep mysql /etc/fstab | wc -l`
    if [ $mysql_fstab -ne 1 ]; then
      echo -e "$RED No /etc/fstab entry for 'mysql'. $NO_COLOR"
      echo " - MYSQL: No /etc/fstab entry." >> $ERROR_LOG
    else
      mysql_fstab_entry=`grep mysql /etc/fstab`
      echo -e " $mysql_fstab_entry $NO_COLOR" >> $MOUNT_LOG
      echo -e " $mysql_fstab_entry $NO_COLOR"
    fi

    echo -en "$GREEN  Checking if starts at boot: $NO_COLOR"
    mysql_boot_time=`/sbin/chkconfig --list | grep mysql | grep 3:on`
    if [ $? -ne 0 ]; then
      echo -e "$RED MySQL is not chkconfig'd to run on runlevel 3. $NO_COLOR"
      echo " - MYSQL: 'chkconfig mysql on' has not been run" >> $ERROR_LOG
    else
      echo -e " MySQL is set to run on runlevel 3"
    fi

    echo -en "$GREEN  Checking mysql:mysql permissions: $NO_COLOR"
    chown mysql:mysql /var/lib/mysql/data/mysql
    mysql_dir_owner=`find /var/lib/mysql -type f | xargs -n1 ls -l | grep -v "mysql mysql" | wc -l`
    if [ $mysql_dir_owner -gt 0 ] ; then
      echo -e "$RED Files under /var/lib/mysql are not ownded by mysql:mysql."
      echo " - MYSQL: Files inside /var/lib/mysql are not owned by mysql:mysql" >> $ERROR_LOG
      for file in "`find /var/lib/mysql -type f | xargs -n1 ls -l | grep -v "mysql mysql"`"
      do
         echo "    $file"
      done
      echo -e "$NO_COLOR"
    fi

    while [ -z $ncdba_pass ] ; do
      echo -n "  Please enter ncdba password: "
      read -s ncdba_pass
    done
    echo

    echo -e " $GREEN Checking database permissions: $NO_COLOR"
    mysql -u ncdba -p$ncdba_pass --batch --skip-column-names -e "select user,password,host from user;" mysql > /tmp/showperms
    #for user in "$users"
    cat /tmp/showperms | while read line
    do
      echo "    $line"
    done
    rm /tmp/showperms

    echo -e " $GREEN Checking database grants: $NO_COLOR"
    tmp=/tmp/showgrant$$
    mysql -u ncdba -p$ncdba_pass --batch --skip-column-names -e "SELECT user, host FROM user" mysql > $tmp
    cat $tmp | while read user host
    do
      echo -n "    "
      mysql -u ncdba -p$ncdba_pass --batch --skip-column-names -e "SHOW GRANTS FOR '$user'@'$host'"
    done
    rm $tmp
  fi

}

check_restore() {
  bacula_ps_count=`ps aux | grep bacula-fd | grep -v grep | wc -l`
  bacula_rpm_count=`rpm -qa | grep bacula-client | wc -l`

  echo -n "$GREEN Checking bacula test-restore: $NO_COLOR"
  if [ $bacula_ps_count -gt 0 ] ; then
    if [ ! -f /tmp/etc/hosts ] ; then
      echo -n "$RED /tmp/etc/hosts not found."
      echo -n "$RED - BACKUP: /tmp/etc/hosts not found. $NO_COLOR" >> $ERROR_LOG
    else
      echo -n "$GREEN /tmp/etc/hosts found."
    fi
  fi
}

check_apache() {
  apache_rpm_check=`yum list installed | grep -i httpd`
  if [ "$apache_rpm_check" > 0 ] ; then
    echo
    echo -e "Apache"
    echo -e "$GREEN  Apache installed. $NO_COLOR"

    echo -en "$GREEN  Checking mount point: $NO_COLOR"
    apache_check_mount=`df -hP | grep -i www`
    if [ $? -ne 0 ]; then
      echo -e "$RED 'www' is not mounted $NO_COLOR"
      echo " - APACHE: No mount point 'www' for apache" >> $ERROR_LOG
    else
      echo -e " - $apache_check_mount $NO_COLOR" >> $MOUNT_LOG
    fi

    echo -en "$GREEN  Checking /etc/fstab: $NO_COLOR"
    apache_fstab=`grep www /etc/fstab | wc -l`
    if [ "$apache_fstab" -ne 1 ]; then
      echo -e "$RED No /etc/fstab entry for 'www' $NO_COLOR"
      echo " - APACHE: No /etc/fstab entry for 'www'" >> $ERROR_LOG
    else
      echo -n " "
      fstab_entry=`grep www /etc/fstab`
      echo " - $fstab_entry" >> $MOUNT_LOG
    fi

    echo -en "$GREEN  Checking netstat:"
    apache_netstat=`netstat -tlpn | grep 'httpd'`
    if [ $? -ne 0 ] ; then
      echo -e "$RED Apache not listening on any port. $NO_COLOR"
      echo " - APACHE: Apache not listening on any port" >> $ERROR_LOG
    else
      echo -e " Apache is running an listening. $NO_COLOR"
    fi
  fi

}

check_nginx() {
  nginx_rpm_check=`yum list installed | grep -i nginx`
  if [ "$nginx_rpm_check" > 0 ] ; then
    echo
    echo -e "Nginx"
    echo -e "$GREEN  Nginx installed. $NO_COLOR"

    echo -en "$GREEN  Checking mount point: $NO_COLOR"
    nginx_check_mount=`df -hP | grep -i www`
    if [ $? -ne 0 ]; then
      echo -e "$RED 'www' is not mounted $NO_COLOR"
      echo " - NGINX: 'www' is not mounted" >> $ERROR_LOG
    else
      echo -e " - $nginx_check_mount $NO_COLOR" >> $MOUNT_LOG
    fi

    echo -en "$GREEN  Checking /etc/fstab: $NO_COLOR"
    nginx_fstab=`grep www /etc/fstab | wc -l`
    if [ $nginx_fstab -lt 1 ]; then
      echo -e "$RED No /etc/fstab entry for 'www' $NO_COLOR"
      echo " - NGINX: No /etc/fstab entry for 'www'" >> $ERROR_LOG
    else
      echo -n " "
      fstab_entry=`grep www /etc/fstab`
      echo " - $fstab_entry" >> $MOUNT_LOG
    fi

    echo -en "$GREEN  Checking netstat:"
    nginx_netstat=`netstat -tlpn | grep 'nginx'`
    if [ $? -ne 0 ] ; then
      echo -e "$RED Nginx not listening on any port. $NO_COLOR"
      echo " - NGINX: Nginx not listening on any port." >> $ERROR_LOG
    else
      echo -e " Nginx is running an listening. $NO_COLOR"
    fi

  fi
}

check_swap() {
  echo
  echo Swap space

  echo -en "$GREEN  Checking /etc/fstab entry: $NO_COLOR"
  swap_fstab=`cat /etc/fstab | grep swap`
  if [ $? -ne 0 ] ; then
    echo -e "$RED No /etc/fstab entry for swap. $NO_COLOR"
    echo " - SWAP: No /etc/fstab entry for swap." >> $ERROR_LOG
  else
    cat /etc/fstab | grep swap
  fi

  echo -en "$GREEN  Checking to see if swap is mounted: $NO_COLOR"
  /sbin/swapon -s > /tmp/swapstats
  cat /tmp/swapstats | while read filename type size rest
  do
    echo " $size"
  done

  swapon=`cat /tmp/swapstats | wc -l`
  if [ "$swapon" -eq 0 ] ; then
    echo -e "$RED Swap is not mounted. $NO_COLOR"
    echo " - SWAP: Swap is not mounted." >> $ERROR_LOG
  fi
  rm /tmp/swapstats

}

check_php() {
  php_package_count=`yum list installed | grep -iE ^php`
  if [ $? -eq 0 ] ; then
    echo
    echo "PHP"
    echo -en "$GREEN  PHP installed: $NO_COLOR"
    php_package_count=`yum list installed | grep -iE ^php | wc -l`
    echo -e " $php_package_count php packages installed $NO_COLOR"

    echo -en "$GREEN  Checking install method: $NO_COLOR"
    if [ -f /home/ncadmin/auto_install/install_php.conf ] ; then
      source /home/ncadmin/auto_install/install_php.conf
      echo -e "Automated install. $NO_COLOR"
      echo -e "$GREEN  Checking module installation: $NO_COLOR"
      for package in ${PHP_EXT[*]}
      do
        php_package=`rpm -qa | grep -iE ^$package`
        if [ $? -ne 0 ] ; then
          echo -e "$RED    $package is not installed. $NO_COLOR"
          echo " - PHP: $package is not installed." >> $ERROR_LOG
#        else
#          echo -e "$GREEN    $package is installed. $NO_COLOR"
        fi
      done
    else
      echo -e "$GREEN Installed manually. $NO_COLOR"
      echo -e "$GREEN  Checking modules: $NO_COLOR"
      php_module=`php -m | grep -v " "`
      for module in $php_modules
      do
         echo "    $module"
      done
    fi

    check_fpm=`rpm -qa | grep php-fpm`
    if [ $? -eq 0 ] ; then
      echo -en "$GREEN  Checking php-fpm boot time options: $NO_COLOR"
      php_fpm_checkconfig=`/sbin/chkconfig --list | grep -i php-fpm | grep 3:on`
      if [ $? -ne 0 ] ; then
        echo -e "$RED php-fpm is will not start after a reboot, need to chkconfig php-fpm on. $NO_COLOR"
        echo " - PHP: php-fpm is will not start after a reboot, need to chkconfig php-fpm on" >> $ERROR_LOG
      else
        echo -e " php-fpm will start on runlevel 3. $NO_COLOR"
      fi
    fi
    php -m > /tmp/check_php

    check_apc=`php -m | grep ^apc`
    if [ $? -eq 0 ] ; then
      echo -e "$GREEN  APC found! $NO_COLOR"
    else
      echo -e "$RED  APC not found! $NO_COLOR"
      echo -e " - PHP: APC not found! "
    fi
  fi
}

check_memcached() {
  memchached_installed=`yum list installed | grep memcached`
  if [ $? -eq 0 ] ; then
    echo
    echo "Memcached"
    echo -e "$GREEN  memcached installed. $NO_COLOR"

    echo -en "$GREEN  Checking if memcached is listening: $NO_COLOR"
    memcached_listen=`netstat -tlpn | grep 'PID\|memcached' | wc -l`
    if [ "$memcached_listen" -lt 2 ] ; then
      echo -e "$RED  memcached is not listening on any port. $NO_COLOR"
      echo " - MEMCACHED: memcached is not listening on any port." >> $ERROR_LOG
    else
      echo -e " memcached is listening. $NO_COLOR"
    fi

    echo -en "$GREEN  Checking to see if memcached to starts at boot: $NO_COLOR"
    memcached_chkconfig=`/sbin/chkconfig --list | grep -i memcached | grep 3:on`
    if [ $? -ne 0 ] ; then
      echo -e "$RED memcached is will not start after a reboot, need to chkconfig memcached on. $NO_COLOR"
      echo " - MEMCACHED: memcached is will not start after a reboot, need to chkconfig memcached on" >> $ERROR_LOG
    else
      echo -e " memcached will start on runlevel 3. $NO_COLOR"
    fi
  fi
}

check_haproxy() {
  haproxy_installed=`yum list installed | grep haproxy`
  if [ $? -eq 0 ] ; then
    echo
    echo "Haproxy"
    echo -e "$GREEN  haproxy installed. $NO_COLOR"

    echo -en "$GREEN  Checking if memcached is listening: $NO_COLOR"
    haproxy_listen=`netstat -tlpn | grep 'PID\|haproxy' | wc -l`
    if [ "$haproxy_listen" -lt 2 ] ; then
      echo -e "$RED haproxy is not listening on any port. $NO_COLOR"
      echo " - HAPROXY: haproxy is not listening on any port." >> $ERROR_LOG
    else
      echo -e " haproxy is listening. $NO_COLOR"
    fi

    echo -en "$GREEN  Checking to see if haproxy starts at boot: $NO_COLOR"
    haproxy_chkconfig=`/sbin/chkconfig --list | grep -i haproxy | grep 3:on`
    if [ $? -ne 0 ] ; then
      echo -e "$RED haproxy is will not start after a reboot, need to chkconfig haproxy on. $NO_COLOR"
      echo " - HAPROXY: haproxy is will not start after a reboot, need to chkconfig haproxy on" >> $ERROR_LOG
    else
      echo -e " haproxy will start on runlevel 3. $NO_COLOR"
    fi

    cat <<EOL > /root/check_haproxy.py
import sys
import commands
servers = commands.getoutput("grep maxconn /etc/haproxy/haproxy.cfg | grep server | grep -v '^[ \t]*#'").split("\n")
for server in servers:
  maxconn = server.split()[-1]
  if int(maxconn) < 2000:
    sys.exit(1)
EOL
    echo -en "$GREEN  Checking maxconn(s): $NO_COLOR"
    python /root/check_haproxy.py
    if [ $? -ne 0 ] ; then
      echo -e "$RED haproxy.cfg has servers that with maxconns < 2000. $NO_COLOR"
      echo " - HAPROXY: haproxy.cfg has servers that with maxconns < 2000" >> $ERROR_LOG
    else
      echo -e " All maxconns >= 2000. $NO_COLOR"
    fi
    rm /root/check_haproxy.py

    echo -en "$GREEN  Checking cookie_names: $NO_COLOR"
    cookie_count=`grep cookie /etc/haproxy/haproxy.cfg | grep insert | grep -v ^# | wc -l`
    cookie_uniq=`grep cookie /etc/haproxy/haproxy.cfg | grep insert | grep -v ^# | uniq | wc -l`
    if [ $cookie_count -ne $cookie_uniq ] ; then
      echo -e "$RED haproxy.cfg has duplicate cookie names. please change SERVERID. $NO_COLOR"
      echo " - HAPROXY: haproxy.cfg has duplicate cookie names. please change SERVERID" >> $ERROR_LOG
    else
      echo -e " Cookie names are uniq. $NO_COLOR"
    fi

    echo -en "$GREEN  Checking /sbin/cnc-haproxy-status: $NO_COLOR"
    if [ -f /sbin/cnc-haproxy-status ] ; then
      echo " Found."
    else
      echo -e " $RED Not found. Please download from svn/nc_scripts $NO_COLOR"
      echo " - HAPROXY: /sbin/cnc-haproxy-status not found. Please download from svn/nc_scripts " >> $ERROR_LOG
    fi

  fi

}

check_ec2() {
  ami_id=`curl -s http://169.254.169.254/latest/meta-data/ami-id`
  if [ $? -eq 0 ] ; then
    echo EC2
    instance_type=`curl -s http://169.254.169.254/latest/meta-data/instance-type`
    private_ip=`curl -s http://169.254.169.254/latest/meta-data/local-ipv4`
    public_ip=`curl -s http://169.254.169.254/latest/meta-data/public-ipv4`
    public_hostname=`curl -s http://169.254.169.254/latest/meta-data/public-hostname`
    region=`curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone`
    security=`curl -s http://169.254.169.254/latest/meta-data/security-groups`

    echo -e "$GREEN  Checking EC2 Region:$NO_COLOR      $region"
    echo -e "$GREEN  Checking AMI ID:$NO_COLOR          $ami_id"
    echo -e "$GREEN  Checking Instance Type:$NO_COLOR   $instance_type"
    echo -e "$GREEN  Checking Instance Tag:$NO_COLOR    No information"
    echo -e "$GREEN  Checking Private IP:$NO_COLOR      $private_ip"
    echo -e "$GREEN  Checking Public IP:$NO_COLOR       $public_ip"
    echo -e "$GREEN  Checking EIP:$NO_COLOR             No Information"
    echo -e "$GREEN  Checking Security Group:$NO_COLOR  $security"
    echo -e "$GREEN  Checking EBS info:$NO_COLOR"
    ebss=`curl -s http://169.254.169.254/latest/meta-data/block-device-mapping/ | grep ebs`
    for ebs in $ebss
    do
      mount_point=`curl -s http://169.254.169.254/latest/meta-data/block-device-mapping/$ebs`
      pvs=`pvs | grep $mount_point`
      echo "    $ebs: $pvs"
    done
  fi
}

check_dom0() {
  if [ -f /usr/sbin/xm ] ; then
    echo
    echo "Dom0"
    echo -e "$GREEN  dom0 found. $NO_COLOR"
  fi
}

check_yum() {
  yum=`yum check-update`
  if [ $? -ne 0 ] ; then
    echo " - YUM: 'yum update' has not been run" >> $ERROR_LOG
  fi
}

check_automated() {
  if [ -f /home/ncadmin/auto_install/server_information.conf ] ; then
    source /home/ncadmin/auto_install/server_information.conf

    free=`python -c "import commands; print commands.getoutput(\"free -m | grep Mem\").split()[1]"`MB
    echo " - RAM: $free "
    if [ "$free" != "$SERVER_RAM" ] ; then
      echo " - OS: Memory does not match spreadsheet." >> $ERROR_LOG
    fi

    cpu_count=`cat /proc/cpuinfo | grep processor | wc -l`CPU
    echo " - CPU COUNT: $cpu_count"
    if [ "$cpu_count" != "$SERVER_VCPU" ] ; then
      echo " - OS: VCPU's does not mache spreadsheet." >> $ERROR_LOG
    fi

    ip1=`cat /etc/sysconfig/network-scripts/ifcfg-eth0 | grep IPADDR |cut -d= -f2`
    echo " - IP1: $ip1"
    ip_check=`grep $ip1 /home/ncadmin/auto_install/server_information.conf`
    if [ $? -ne 0 ] ; then
      echo " - OS: $ip1 does not match ip information in spreadsheet" >> $ERROR_LOG
    fi

    if [ -f /etc/sysconfig/network-scripts/ifcfg-eth1 ] ; then
      ip2=`cat /etc/sysconfig/network-scripts/ifcfg-eth1 | grep IPADDR |cut -d= -f2`
      ip_check=`grep $ip2 /home/ncadmin/auto_install/server_information.conf`
      echo " - IP1: $ip2"
      if [ $? -ne 0 ] ; then
        echo " - OS: $ip2 does not match ip information in spreadsheet" >> $ERROR_LOG
      fi
    fi

    df_gw=`python -c "import commands; print commands.getoutput(\"route -n | grep 0.0.0.0 | grep UG\").split()[1]"`
    echo " - DF GW: $df_gw"
    if [ ! -z $SERVER_GATEWAY ] ; then
      if [ "$df_gw" != "$SERVER_GATEWAY" ] ; then
        echo " - OS: Default gateway does not match spreadsheet."  >> $ERROR_LOG
      fi
    fi

    ping_df_gw=`ping $df_gw -c 1 | head -n2 | tail -n1 | grep ms`
    if [ $? -eq 1 ] ; then
      echo " - DF GW: NOT PINGABLE"  >> $ERROR_LOG
    else
      echo " - DF GW: PINGABLE"
    fi

    echo " - NAMESERVERS: "
    if [ ! -z $SERVER_DNS_1 ] ; then
      check_dns=`grep $SERVER_DNS_1 /etc/resolv.conf`
      echo "     $check_dns"
      if [ $? -ne 0 ] ; then
        echo " - OS: $SERVER_DNS_1 is in the the spreadsheet, but not in /etc/resolv.conf." >> $ERROR_LOG
      fi
    fi

#    google_ns=`cat /etc/resolv.conf | grep nameserver | grep 8.8.8.8`
#    if [ $? -eq 0 ] ; then
#      echo " - DNS: Google nameservers found in /etc/resolv.conf" >> $ERROR_LOG
#    fi

    if [ ! -z $SERVER_DNS_2 ] ; then
      check_dns=`grep $SERVER_DNS_2 /etc/resolv.conf`
      echo "     $check_dns"
      if [ $? -ne 0 ] ; then
        echo " - OS: $SERVER_DNS_2 is in the the spreadsheet, but not in /etc/resolv.conf." >> $ERROR_LOG
      fi
    fi

    syslog=`grep 61.129.13.23 /etc/syslog-ng/syslog-ng.conf | grep -E "^dest"`
    if [ $? -eq 1 ] ; then
      echo " - SYSLOG: syslog not setup properly "  >> $ERROR_LOG
    fi

    if [ -f /home/ncadmin/auto_install/customer_users.conf ] ; then
      source /home/ncadmin/auto_install/customer_users.conf
      echo " - USERS/PASSWORD EXPIRE/LAST LOGIN:"
      for user in ${OS_USER[*]}
      do
        user_name=`echo "$user" | cut -d":" -f1`
        passwd_check=`grep $user_name /etc/passwd`
        if [ $? -eq 0 ] ; then
          expire=`chage -l $user_name | grep "Password expires" | cut -d":" -f2`
          last=`python -c "import commands; print commands.getoutput(\"last | grep $user_name\").split(\"  \")[-3]" 2> /dev/null`
          echo "     $user_name /$expire / $last"
        else
          echo " - OS: User: $user_name not created." >> $ERROR_LOG
        fi
      done
    fi
  else
    MANUAL=1
  fi
}

check_manual() {
  free=`python -c "import commands; print commands.getoutput(\"free -m | grep Mem\").split()[1]"`MB
  echo " - RAM: $free "

  cpu_count=`cat /proc/cpuinfo | grep processor | wc -l`CPU
  echo " - CPU COUNT: $cpu_count"

  ip1=`cat /etc/sysconfig/network-scripts/ifcfg-eth0 | grep IPADDR |cut -d= -f2`
  echo " - IP1: $ip1"

  if [ -f /etc/sysconfig/network-scripts/ifcfg-eth1 ] ; then
    ip2=`cat /etc/sysconfig/network-scripts/ifcfg-eth1 | grep IPADDR |cut -d= -f2`
    echo " - IP2: $ip2 "
  fi

  df_gw=`python -c "import commands; print commands.getoutput(\"route -n | grep 0.0.0.0 | grep UG\").split()[1]"`
  echo " - DF GW: $df_gw"

  ping_df_gw=`ping $df_gw -c 1 | head -n2 | tail -n1 | grep ms`
  if [ $? -eq 0 ] ; then
    echo " - DF GW: Pingable"
  else
    echo " - DF GW: NOT PINGABLE"
  fi

  nameservers=`cat /etc/resolv.conf | grep nameserver`
  echo " - NAMESERVERS: "
  for nameserver in $nameservers
  do
    echo "     $nameserver"
  done

  syslog=`grep 61.129.13.23 /etc/syslog-ng/syslog-ng.conf | grep -E "^dest"`
  if [ $? -eq 1 ] ; then
    echo " - SYSLOG: syslog not setup properly "  >> $ERROR_LOG
  fi

  sendmail=`grep -E "^Dj" /etc/mail/sendmail.cf`
  if [ $? -eq 1 ] ; then
    echo " - SENDMAIL: sendmail has not been fixed. (https://wiki.service.chinanetcloud.com/wiki/Operations:NC-OP_TP-539-Fix_sendmail_on_customer_servers)"  >> $ERROR_LOG
  fi

#  google_ns=`cat /etc/resolv.conf | grep nameserver | grep 8.8.8.8`
#  if [ $? -eq 0 ] ; then
#    echo " - DNS: Google nameservers found in /etc/resolv.conf" >> $ERROR_LOG
#  fi

  users=`cat /etc/passwd | grep -E ".*:x:5[0-9][0-9]" | cut -d: -f1`
  echo " - USERS/PASSWORD EXPIRE/LAST LOGIN:"
  for user in $users
  do
    expire=`chage -l $user | grep "Password expires" | cut -d":" -f2`
    last=`python -c "import commands; print commands.getoutput(\"last | grep $user\").split(\"  \")[-3]" 2> /dev/null`
    echo "     $user /$expire / $last"
  done

  sshers=`cat /etc/group | grep sshers | cut -d":" -f4`
  echo " - SSHERS:"
  echo "     $sshers"



}

check_firewall() {
  policy=`/sbin/iptables -nvL | grep "policy ACCEPT" | wc -l`
  if [ $policy -gt 1 ] ; then
    echo " - FIREWALL: Firewall is in test mode, or not installed properly. " >> $ERROR_LOG
  fi

}

echo "Checking OS..." > /tmp/qa_result.txt
check_swap >> $INSTALL_LOG
check_dom0 >> $INSTALL_LOG
#check_yum >> $INSTALL_LOG
check_automated >> $INFORMATION_LOG
if [ "$MANUAL" = 1 ] ; then
  check_manual >> $INFORMATION_LOG
fi
#check_firewall >> $INSTALL_LOG
check_ec2 >> $INFORMATION_LOG
#check_restore >> $INSTALL_LOG
echo "Checking Software..." >> /tmp/qa_result.txt
check_mysql
#check_apache >> $INSTALL_LOG
check_nginx >> $INSTALL_LOG
check_php >> $INSTALL_LOG
check_memcached >> $INSTALL_LOG
check_haproxy >> $INSTALL_LOG

echo '
"#######################################################"
"# Summary                                             #"
"#######################################################"
"Information: " ' >> /tmp/qa_result.txt
cat $INFORMATION_LOG >> /tmp/qa_result.txt


echo "Mounts: " >> /tmp/qa_result.txt
cat $MOUNT_LOG >> /tmp/qa_result.txt


echo "Errors:" >> /tmp/qa_result.txt
cat $ERROR_LOG >> /tmp/qa_result.txt


echo "Notes:" >> /tmp/qa_result.txt
echo " - Please check $INSTALL_LOG" >> /tmp/qa_result.txt


### Binary Definition ###
MAIL=/bin/mail
EMAIL_ADDRESS1=pm_auto_notify@chinanetcloud.com
EMAIL_ADDRESS2=
EMAIL_ADDRESS3=
EMAIL_ADDRESS4=
EMAIL_ADDRESS5=
EMAIL_ADDRESS6=

DATE=$(date "+%Y%m%d")
QA_REPORT=/tmp/qa_result.txt
HOSTNAME=$(hostname)

# Send email
echo "Please check the attachment" | $MAIL -s "QA Result Report on $HOSTNAME - $DATE " $EMAIL_ADDRESS1 -c $EMAIL_ADDRESS2,$EMAIL_ADDRESS5,$EMAIL_ADDRESS6 < $QA_REPORT
