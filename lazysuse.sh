#!/bin/bash
# OpenSUSE Configuration and Updater version 2.0
# Optimized for OpenSUSE 11.3
# Please contact dteo827@gmail.com with bugs or feature requests

""
"Computer info: \nVersion:" >> changes
lsb_release -r >> changes
uname -r >> file
date >> changes
dpkg -l >> file

clear
version="2.0"
#some variables
DEFAULT_ROUTE=$(ip route show default | awk '/default/ {print $3}')
IFACE=$(ip route show | awk '(NR == 2) {print $3}')
JAVA_VERSION=`java -version 2>&1 |awk 'NR==1{ gsub(/"/,""); print $3 }'`
MYIP=$(ip route show | awk '(NR == 2) {print $9}')

if [ $UID -ne 0 ]; then
    echo -e "\033[31This program must be run as root.This will probably fail.\033[m"
    sleep 3
    fi

###### Install script if not installed
if [ ! -e "/usr/bin/lazysuse" ];then
        echo "Script is not installed. Do you want to install it ? (Y/N)"
        read install
        if [[ $install = Y || $install = y ]] ; then
                cp -v $0 /usr/bin/lazysuse
                chmod +x /usr/bin/lazysuse
                #rm $0
                echo "Script should now be installed. Launching it !"
                sleep 3
                lazysuse
                exit 1
        else
                echo -e "\e[32m[-] Ok,maybe later !\e[0m"
        fi
else
        echo "Script is installed"
        sleep 1
fi
### End of install process

#### pause function
function pause(){
   read -sn 1 -p "Press any key to continue..."
}

#### credits
function credits {
clear
echo -e "
\033[31m#######################################################\033[m
                       Credits To
\033[31m#######################################################\033[m"
echo -e "\033[36m
David Teo For Making the script.
Pashapasta for the idea and version 1.0
lazykali.sh for UI 
Adam Shuman for mysql stuff

and anyone else I may have missed.

\033[m"
}

#### Screwup function
function screwup {
        echo "You Screwed up somewhere, try again."
        pause 
        clear
}

######## Update OpenSuse
function answerUpdate {
        echo "This will fully update OpenSUSE, this will take a while. Do you want to do this? (Y/N)"
        read install
        if [[ $install = Y || $install = y ]] ; then
                echo -e "\e[31m[+] Updating OpenSUSE now! \nHope you have some time to burn... \e[0m"
                zypper ar -f http://ftp5.gwdg.de/pub/opensuse/discontinued/distribution/11.3/repo/non-oss/ non_oss
                zypper ar -f http://ftp5.gwdg.de/pub/opensuse/discontinued/distribution/11.3/repo/oss oss
                sudo zypper refresh
                sudo zypper up
                echo "Fully Updated OpenSUSE release, this task was completed at: " $(date) >> changes
                echo -e "\e[32m[-] Done Updating!\e[0m"           
        else
                echo -e "\e[32m[-] Ok,maybe later !\e[0m"
        fi

}
#############################
#    Hardening Scripts      #
#############################

######## Iptables install
function iptables {
    echo "This will disable login on all accounts except the ones made during/after install. Do you want to do this? (Y/N)"
    read install
    if [[ $install = Y || $install = y ]] ; then
        echo -e "\e[31m[+] Resetting now!\e[0m"
        #iptables -A INPUT -p udp --dport 9100 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -s 
        #iptables -A OUTPUT -p udp --sport 9100 -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        #make temp file for local ip
        localIP= 10.10.103.15
        serverIP= 10.10.103.5
        gateway=10.10.103.1
        subnet=10.10.103.0/8
        
        SPAMLIST="blockedip"
        SPAMDROPMSG="BLOCKED IP DROP"
         
        echo "Starting IPv4 Wall..."
        /usr/sbin/iptables -F
        /usr/sbin/iptables -X
        /usr/sbin/iptables -t nat -F
        /usr/sbin/iptables -t nat -X
        /usr/sbin/iptables -t mangle -F
        /usr/sbin/iptables -t mangle -X
        modprobe ip_conntrack
         
        [ -f /root/scriptabless/blocked.ips.txt ] && BADIPS=$(egrep -v -E "^#|^$" /root/scriptabless/blocked.ips.txt)
         
        PUB_IF="eth0"
         
        #unlimited 
        /usr/sbin/iptables -A INPUT -i lo -j ACCEPT
        /usr/sbin/iptables -A OUTPUT -o lo -j ACCEPT
         
        # DROP all incomming traffic
        /usr/sbin/iptables -P INPUT DROP
        /usr/sbin/iptables -P OUTPUT DROP
        /usr/sbin/iptables -P FORWARD DROP
         
        if [ -f /root/scriptabless/blocked.ips.txt ];
        then
        # create a new iptablesables list
        /usr/sbin/iptables -N $SPAMLIST
         
        for ipblock in $BADIPS
        do
           iptables -A $SPAMLIST -s $ipblock -j LOG --log-prefix "$SPAMDROPMSG"
           iptables -A $SPAMLIST -s $ipblock -j DROP
        done
         
        /usr/sbin/iptables -I INPUT -j $SPAMLIST
        /usr/sbin/iptables -I OUTPUT -j $SPAMLIST
        /usr/sbin/iptables -I FORWARD -j $SPAMLIST
        fi
         
        # Block sync
        /usr/sbin/iptables -A INPUT -i ${PUB_IF} -p tcp ! --syn -m state --state NEW  -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Drop Sync"
        /usr/sbin/iptables -A INPUT -i ${PUB_IF} -p tcp ! --syn -m state --state NEW -j DROP
         
        # Block Fragments
        /usr/sbin/iptables -A INPUT -i ${PUB_IF} -f  -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fragments Packets"
        /usr/sbin/iptables -A INPUT -i ${PUB_IF} -f -j DROP
         
        # Block bad stuff
        /usr/sbin/iptables  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
        /usr/sbin/iptables  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL ALL -j DROP
         
        /usr/sbin/iptables  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "NULL Packets"
        /usr/sbin/iptables  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL NONE -j DROP # NULL packets
         
        /usr/sbin/iptables  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
         
        /usr/sbin/iptables  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "XMAS Packets"
        /usr/sbin/iptables  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP #XMAS
         
        /usr/sbin/iptables  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fin Packets Scan"
        /usr/sbin/iptables  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags FIN,ACK FIN -j DROP # FIN packet scans
         
        /usr/sbin/iptables  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
         
        # Allow full outgoing connection but no incomming stuff
        /usr/sbin/iptables -A INPUT -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
        /usr/sbin/iptables -A OUTPUT -o eth0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
         
        # Allow ssh 
        /usr/sbin/iptables -A INPUT -p tcp --destination-port 22 -j ACCEPT
         
        # allow incomming ICMP ping pong stuff
        /usr/sbin/iptables -A INPUT -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
        /usr/sbin/iptables -A OUTPUT -p icmp --icmp-type 0 -m state --state ESTABLISHED,RELATED -j ACCEPT
         
        # Allow port 53 tcp/udp (DNS Server)
        #iptables -A INPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
        #iptables -A OUTPUT -p udp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT
         
        #iptables -A INPUT -p tcp --destination-port 53 -m state --state NEW,ESTABLISHED,RELATED  -j ACCEPT
        #iptables -A OUTPUT -p tcp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT
         
        # Open port 80
        /usr/sbin/iptables -A INPUT -p tcp --destination-port 80 -j ACCEPT
        ##### Add your rules below ######
         
        ##### END your rules ############
         
        # Do not log smb/windows sharing packets - too much logging
        /usr/sbin/iptables -A INPUT -p tcp -i eth0 --dport 137:139 -j REJECT
        /usr/sbin/iptables -A INPUT -p udp -i eth0 --dport 137:139 -j REJECT
         
        # log everything else and drop
        /usr/sbin/iptables -A INPUT -j LOG
        /usr/sbin/iptables -A FORWARD -j LOG
        /usr/sbin/iptables -A INPUT -j DROP
        echo "iptables secured, this task was completed at: " $(date) >> changes
        echo -e "\e[32m[-] Done securing iptables !\e[0m"           
    else
        echo -e "\e[32m[-] Ok,maybe later !\e[0m"
    fi     
}
######## disabling non-critical accounts 
function disableAccounts {
        echo "This will disable login on all accounts except the ones made during/after install. Do you want to do this? (Y/N)"
        read install
        if [[ $install = Y || $install = y ]] ; then
                echo -e "\e[31m[+] Resetting now!\e[0m"
                passwd at -l
                passwd avahi -l
                passwd bin -l
                passwd daemon -l
                passwd dnsmasq -l
                passwd ftp -l
                passwd games -l
                passwd gdm -l
                passwd haldaemon -l
                passwd lp -l
                passwd mail -l
                passwd man -l
                passwd messagebus -l
                passwd news -l
                passwd nobody -l
                passwd ntp -l
                passwd polkituser -l
                passwd postfix -l
                passwd pulse -l
                passwd rtkit -l
                passwd sshd -l
                passwd suse-ncc -l
                passwd uucp -l
                passwd wwwrun -l
                echo "All accounts disabled, this task was completed at: " $(date) >> changes
                echo -e "\e[32m[-] Done disabling accounts !\e[0m"           
        else
                echo -e "\e[32m[-] Ok,maybe later !\e[0m"
        fi        
}

######## resetMysql 
function resetMysql {
        echo "This will reset the mysql password. Do you want to do this? (Y/N)"
        read install
        if [[ $install = Y || $install = y ]] ; then
                echo -e "\e[31m[+] Resetting now!\e[0m"
                kill `ps aux | grep mysqld`
                read -p "What would you like the password to be? " password
                sudo echo UPDATE mysql.user SET Password='$password' WHERE User='root';'\n'FLUSH PRIVILEGES;'\n'quit; >> /root/mysql-init
                mysqld_safe --init-file=/root/mysql-init
                rm /home/root/mysql-init
                /etc/init.d/mysql restart
                echo "Reset mySQL Password, this task was completed at: " $(date) >> changes
                echo -e "\e[32m[-] Done resetting mysql !\e[0m"           
        else
                echo -e "\e[32m[-] Ok,maybe later !\e[0m"
        fi        
}

######## Fix Shellshock
function answerShellshock {
        echo "This will fix shellshock. Do you want to do this ? (Y/N)"
        read install
        if [[ $install = Y || $install = y ]] ; then
                echo -e "\e[31m[+] Installing PROGRAM now!\e[0m"
                cd /src
                wget http://ftp.gnu.org/gnu/bash/bash-4.3.tar.gz
                #download all patches
                for i in $(seq -f "%03g" 1 28); do wget http://ftp.gnu.org/gnu/bash/bash-4.3-patches/bash43-$i; done
                tar zxvf bash-4.3.tar.gz
                cd bash-4.3
                #apply all patches
                for i in $(seq -f "%03g" 1 28);do patch -p0 < ../bash43-$i; done
                #build and install
                ./configure --prefix=/ && make && make install
                cd ../../
                rm -r src
                echo "Fixed Shellshock vulnerability, this task was completed at: " $(date) >> changes
                echo -e "\e[32m[-] Shellshock fixed !\e[0m"           
        else
                echo -e "\e[32m[-] Ok,maybe later !\e[0m"
        fi        
}

#### HardeningScripts
function answerHardeningScripts {
clear
echo -e "
\033[31m#######################################################\033[m
                Hardening Scripts
\033[31m#######################################################\033[m"

select menusel in "Secure iptables" mySQL" "Shellshock" "Disable all other Accounts" "Install All" "Back to Main"; do
case $menusel in
        "Secure iptables")
                iptables
                pause
                answerHardeningScripts ;;
        "mySQL")
                resetMysql
                pause
                answerHardeningScripts ;;
                
        "Shellshock")
                answerShellshock
                pause
                answerHardeningScripts ;;

        "Disable all other Accounts")
                disableAccounts
                pause
                answerHardeningScripts ;;

        "Install All")
                echo -e "\e[31m[+] Installing Extra's\e[0m"
                answerMysql
                answershellshock
                disableAccounts
                echo -e "\e[32m[-] Done Installing Extra's\e[0m"
                pause
                answerHardeningScripts ;;         

        "Back to Main")
                clear
                mainmenu ;;
                
        *)
                screwup
                answerHardeningScripts ;;
               
esac

break

done
}

##########################################
#           Defense Programs             #
##########################################

######## Install OSSEC
function answerOSSEC {
        echo "This is not yet implemented"
        #echo "This will install OSSEC. Do you want to install it ? (Y/N)"
        #read install
        #if [[ $install = Y || $install = y ]] ; then
        #        echo -e "\e[31m[+] Installing OSSEC now!\e[0m"
        #        cd /tmp
        #        
        #        echo -e "\e[32m[-] Done Installing OSSEC!\e[0m"           
        #else
        #        echo -e "\e[32m[-] Ok,maybe later !\e[0m"
        #fi        
}

######## Install Nessus
function answerNessus {
        echo "This will install Nessus. Do you want to install it ? (Y/N)"
        read install
        if [[ $install = Y || $install = y ]] ; then
                echo -e "\e[31m[+] Installing Nessus now!\e[0m"
                cd /tmp
                wget http://downloads.nessus.org/nessus3dl.php?file=Nessus-6.3.3-suse11.i586.rpm&licence_accept=yes&t=3cc0e52131cd121bbda2ee0190a4f224 --
                echo "Installed Nessus, this task was completed at: " $(date) >> changes
                echo -e "\e[32m[-] Done Installing Nessus!\e[0m"           
        else
                echo -e "\e[32m[-] Ok,maybe later !\e[0m"
        fi        
}

######## Install Nmap
function answerNmap {
        echo "This will install Nmap. Do you want to install it ? (Y/N)"
        read install
        if [[ $install = Y || $install = y ]] ; then
                echo -e "\e[31m[+] Installing Nmap now!\e[0m"
                cd /tmp
                zypper install nmap
                echo "Installed Nmap, this task was completed at: " $(date) >> changes
                echo -e "\e[32m[-] Done Installing Nmap!\e[0m"           
        else
                echo -e "\e[32m[-] Ok,maybe later !\e[0m"
        fi        
}


######## Install Artillery
function answerArtillery {
        echo "This will install Artillery. Do you want to install it ? (Y/N)"
        read install
        if [[ $install = Y || $install = y ]] ; then
                echo -e "\e[31m[+] Installing Artillery now!\e[0m"
                cd /tmp
                git clone git://github.com/trustedsec/artillery
                cd artillery
                ./setup.py
                echo "Installed Artillery, this task was completed at: " $(date) >> changes
                echo -e "\e[32m[-] Done Installing Artillery!\e[0m"           
        else
                echo -e "\e[32m[-] Ok,maybe later !\e[0m"
        fi        
}


######## Install Nikto
function answerNikto {
        echo "This will install Nikto. Do you want to install it ? (Y/N)"
        read install
        if [[ $install = Y || $install = y ]] ; then
                echo -e "\e[31m[+] Installing Nikto now!\e[0m"
                cd /tmp
                wget https://github.com/sullo/nikto/archive/master.zip --no-check-certificate
                unzip nikto-master.zip
                cd nikto-master
                cd program
                chmod a+x nikto.pl 
                chmod 777 nikto.pl
                ./nikto.pl -host localhost
                echo "Installed Nikto, this task was completed at: " $(date) >> changes
                echo -e "\e[32m[-] Done Installing Nikto!\e[0m"           
        else
                echo -e "\e[32m[-] Ok,maybe later !\e[0m"
        fi        
}

######## Install Fail2ban
function answerFail2ban {
        echo "This will install Fail2ban . Do you want to install it ? (Y/N)"
        read install
        if [[ $install = Y || $install = y ]] ; then
                echo -e "\e[31m[+] Installing Fail2ban now!\e[0m"
                cd /tmp
                zypper ar -f -n packman http://packman.inode.at/suse/openSUSE_11.3/ packman
                sudo yast2 -i fail2ban 
                sudo chkconfig --add fail2ban 
                sudo /etc/init.d/fail2ban start
                /etc/init.d/fail2ban start
                echo "Installed Fail2ban, this task was completed at: " $(date) >> changes
                echo -e "\e[32m[-] Done Installing Fail2ban!\e[0m"           
        else
                echo -e "\e[32m[-] Ok,maybe later !\e[0m"
        fi        
}


######## Install Lynis
function answerLynis {
        echo "This will install Lynis. Do you want to install it ? (Y/N)"
        read install
        if [[ $install = Y || $install = y ]] ; then
                echo -e "\e[31m[+] Installing Lynis now!\e[0m"
                cd /tmp
                wget https://cisofy.com/files/lynis-2.0.0.tar.gz -O lynis.tar.gz --no-check-certificate
                tar -zxvf lynis.tar.gz
                cd lynis
                sudo chmod 777 lynis
                sudo chmod a+x lynis
                chown root ./inculde/consts
                chown root ./inculde/functions
                chgrp root ./inculde/osdetection
                chown root ./inculde/profiles
                chgrp root ./inculde/binaries
                sudo ./lynis -q audit system --log-file /home/lynis_output
                cd /home/Downloads
                echo "Installed Lynis, this task was completed at: " $(date) >> changes
                echo -e "\e[32m[-] Done Installing Lynis!\e[0m"           
        else
                echo -e "\e[32m[-] Ok,maybe later !\e[0m"
        fi        
}

function answerDefense {
clear
echo -e "
\033[31m#######################################################\033[m
                Install Defense Programs
\033[31m#######################################################\033[m"

select menusel in "Lynis" "Fail2ban" "Nikto" "Nmap" "Nessus" "OSSEC" "Artillery" "Install All" "Back to Main"; do
case $menusel in
        "Lynis")
                answerLynis
                pause 
                answerDefense;;
                
        "Fail2ban")
                answerFail2ban
                pause
                answerDefense;;
                
        "Nikto")
                answerNikto
                pause 
                answerDefense;;
                
        "Nmap")
                answerNmap
                pause 
                answerDefense;;
                
        "Nessus")
                answerNessus
                pause 
                answerDefense;;
                
        "OSSEC")
                answerOSSEC
                pause 
                answerDefense;;
                                
        "Artillery")
                answerArtillery
                pause 
                answerDefense ;;
                
        "Install All")
                echo -e "\e[31m[+] Installing Extra's\e[0m"
                answerLynis
                answerFail2ban
                answerNikto
                answerNmap
                answerNessus
                answerOSSEC
                answerArtillery
                echo -e "\e[32m[-] Done Installing Extra's\e[0m"
                pause
                answerDefense ;;         

        "Back to Main")
                clear
                mainmenu ;;
                
        *)
                screwup
                answerDefense ;;
        
                
esac

break

done
}

########################################################
##             Main Menu Section
########################################################
function mainmenu {
echo -e "
\033[31m################################################################\033[m
\033[1;36m
.____                          .____        .____  .____
|    |   _____  ___________.__.|      |    ||      |
|    |   \__  \ \___   <   |  ||____. |    ||____. |____
|    |___ / __ \_/    / \___  |     | |    |     | |
|_______ (____  /_____ \/ ____| ____| |____| ____| |____
        \/    \/      \/\/                          

\033[m                                        
                   Script by dteo827
                    version : \033[32m$version\033[m
Script Location : \033[32m$0\033[m
Connection Info :-----------------------------------------------
  Gateway: \033[32m$DEFAULT_ROUTE\033[m Interface: \033[32m$IFACE\033[m My LAN Ip: \033[32m$MYIP\033[m
\033[31m################################################################\033[m"

select menusel in "Update SUSE" "Hardening Scripts" "Defense Programs" "HELP!" "Credits" "EXIT PROGRAM"; do
case $menusel in
        "Update SUSE")
                answerUpdate
                clear ;;
        
        "Hardening Scripts")
                answerHardeningScripts
                clear ;;
                        
        "Defense Programs")
                answerDefense
                clear ;;
        
        "HELP!")
                echo "What do you need help for, seems pretty simple!"
                pause
                clear ;;
                
        "Credits")
                credits
                pause
                clear ;;

        "EXIT PROGRAM")
                clear && exit 0 ;;
                
        * )
                screwup
                clear ;;
esac

break

done
}

while true; do mainmenu; done
