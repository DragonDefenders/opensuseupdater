#!/bin/bash
# OpenSUSE Configuration and Updater version 1.0
# Optimized for OpenSUSE 11.3 #!/bin/bash
# Thanks to Pashapasta for the script template, check out the Kali version at https://github.com/PashaPasta/KaliUpdater/blob/master/KaliConfigAndUpdate.sh
# Please contact dteo827@gmail.com with bugs or feature requests

printf "

                    #############################
                    # OpenSUSE Security & Updates #
                    #############################
                    
                   #################################
                   #This script MUST be run as root#
                   #################################
                    
    ##############################################################
    # Welcome, you will be presented with a few questions, please#
    #          answer [y/n] according to your needs.             #
    ##############################################################\n\n"

# Questions function
function questions() {
read -p "Do you want to add Google's and Level3's Public DNS to the resolv.conf file? [y/n] " answerGoogleDNS
read -p "Do you want to install *ONLY* security updates to OpenSUSE Linux now? [y/n] " answerSecUpdate
read -p "Do you want to install *ALL* updates to OpenSUSE Linux now? [y/n] " answerUpdate
#read -p "Do you want to turn off root login, Ipv6, keep boot as read only,and ignore ICMP broadcast requests and prevent XSS attacks? [y/n] " answermasshardening
read -p "Do you want to install Lynis [y/n] " answerLynis
read -p "Do you want to install Fail2ban [y/n] " answerFail2ban
}

echo "version"
lsb_release -r >> file
uname -r >> file
echo date >> file
echo
echo "my name" >> file
echo
echo dpkg -l >> file

# Flags!!!!
# If script run with -a flag, all options will automatically default to yes

if [[ $1 = -a ]] ; then

    read -p "Are you sure you want to install all packages and configure everything by default? Only Security Updates will be installed [y/n] " answerWarning
    if [[ $answerWarning = y ]] ; then
        answerGoogleDNS=y
        answerSecUpdate=y
        answermasshardening=y
        answerBastille=y
        answerLynis=y
        answerFail2ban=y
        answermySQL=y
    else
        printf "Verify what you do and do not want done.... "
        sleep 2
        questions
fi

else
    echo "unknown command"
    questions
fi

# Logic for update and configuration steps

if [[ $answerGoogleDNS = y ]] ; then

    sudo echo nameserver 8.8.8.8 >> /etc/resolv.conf
    sudo echo nameserver 8.8.4.4 >> /etc/resolv.conf
    sudo echo nameserver 4.2.2.2 >> /etc/resolv.confs
    echo "Updated DNS resolutions to Google DNS, this task was completed at: " $(date) >> changes
fi

if [[ $answerUpdate = y ]] ; then
    printf "Updating OpenSUSE, this stage may take about an hour to complete...Hope you have some time to burn... \n"
    zypper ar -f http://ftp5.gwdg.de/pub/opensuse/discontinued/distribution/11.3/repo/non-oss/ non_oss
    zypper ar -f http://ftp5.gwdg.de/pub/opensuse/discontinued/distribution/11.3/repo/oss oss
    sudo zypper refresh
	sudo zypper up

    echo "Fully Updated OpenSUSE release, this task was completed at: " $(date) >> changes
fi


if [[ $answermasshardening = y ]] ; then  
    #sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config  #automated above lines for ssh config
    sudo echo Ignore ICMP request: >> /etc/sysctl.conf
    sudo echo net.ipv4.icmp_echo_ignore_all = 1 >> /etc/sysctl.conf
    sudo echo Ignore Broadcast request: >> /etc/sysctl.conf
    sudo echo net.ipv4.icmp_echo_ignore_broadcasts = 1 >> /etc/sysctl.conf
    sudo echo net.ipv6.conf.all.disable_ipv6 = 1 >> /etc/sysctl.conf
    sudo echo net.ipv6.conf.default.disable_ipv6 = 1 >> /etc/sysctl.conf
    sudo echo net.ipv6.conf.lo.disable_ipv6 = 1 >> /etc/sysctl.conf
    sudo sysctl -p
fi

if [[ $answerBastille = y ]] ; then
    http://downloads.sourceforge.net/project/bastille-linux/bastille-linux/3.0.9/Bastille-3.0.9.tar.bz2?r=http%3A%2F%2Fbastille-linux.sourceforge.net%2Fsource.htm&ts=1427055483&use_mirror=tcpdiag
    tar -xjvf Bastille-3.0.9.tar.bz2
    cd Bastille
    chmod 777 Install.sh
    chmod a+x Install.sh
    sudo ./Install.sh
fi

if [[ $answerLynis = y ]] ; then
    wget https://cisofy.com/files/lynis-2.0.0.tar.gz -O lynis.tar.gz --no-check-certificate
    tar -zxvf lynis.tar.gz
    cd Downloads
    cd lynis
    chmod 777 lynis
    chmod a+x lynis
    chmod 640 ./include/consts
    chmod 640 ./include/functions
    chown root ./include/consts
    chown root ./include/functions
    chown root ./include/osdetection
    ./lynis -q audit system --log-file /home/lynis_output
    cd /home/Downloads
fi

if [[ $answerFail2ban = y ]] ; then
    zypper ar -f -n packman http://packman.inode.at/suse/openSUSE_11.3/ packman
    yast2 -i fail2ban 

    chkconfig --add fail2ban 
    /etc/init.d/fail2ban start
fi

if [[ $answermySQL = y ]] ; then
    kill `ps aux | grep mysqld`
    read -p "What would you like the password to be? " password
    sudo echo UPDATE mysql.user SET Password='$password' WHERE User='root';'\n'FLUSH PRIVILEGES; >> /root/mysql-init
    mysqld_safe --init-file=/root/mysql-init
    rm /home/root/mysql-init
    /etc/init.d/mysql restart
    echo "Installed mySQL, this task was completed at: " $(date) >> changes
fi


echo "version"
lsb_release -r >> file
uname -r >> file
echo date >> file
echo
echo "my name" >> file
echo
echo dpkg -l >> file



function pause () {
        read -p "$*"
}

pause '
Press [Enter] key to exit...
'
