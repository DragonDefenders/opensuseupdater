#!/bin/bash
read -p "Are you sure you want to diable login on all acocunts except the secondary and root accounts? [y/n] " doublecheck
read -p "Do you want to disable root login? [y/n] " disableroot
if [[ $doublecheck = y ]] ; then
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
  echo "Disabled login to all non critical acounts, this task was completed at: " $(date) >> changes
fi
if [[ $disableroot = y ]] ; then
  sudo passwd root -l
  echo "Disabled root login , this task was completed at: " $(date) >> changes
fi

