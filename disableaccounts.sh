#!/bin/bash
sudo passwd at -l
sudo passwd avahi -l
sudo passwd bin -l
sudo passwd daemon -l
sudo passwd dnsmasq -l
sudo passwd ftp -l
sudo passwd games -l
sudo passwd gdm -l
sudo passwd haldaemon -l
sudo passwd lp -l
sudo passwd mail -l
sudo passwd man -l
sudo passwd messagebus -l
sudo passwd news -l
sudo passwd nobody -l
sudo passwd ntp -l
sudo passwd polkituser -l
sudo passwd postfix -l
sudo passwd pulse -l
sudo passwd rtkit -l
sudo passwd sshd -l
sudo passwd suse-ncc -l
sudo passwd uucp -l
sudo passwd wwwrun -l
sudo passwd root -l
echo "Disabled login to all acounts except secondary administrator account and , this task was completed at: " $(date) >> changes
