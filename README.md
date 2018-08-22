# check_asterisk_ami8

This is a nagios check command that checks an Asterisk based server through the AMI interface.

So far it checks:
  - peers
    - SIP
    - PJSIP
    - IAX2
  - Current Calls
  - Current Channels

Quick note --
 AMI Interface must be enabled (in manager.conf), firewall cannot be blocking AMI port (default: 5038)
 For Freepbx you can add something like this to manager_custom.conf

[MonitorUser]

secret = MonitorPass

writetimeout = 500

read = command

But PLEASE change the user/password

Examples:
 ./check_asterisk_ami8 -H localhost -u MonitorUser -p MonitorPass -q pjsippeers
   Check all pjsippeers, raise Critical if any are Down

 ./check_asterisk_ami8 -H localhost -u MonitorUser -p MonitorPass -q sippeers -I -i pots1
   Check the sip peer pots1 and rais Critical if it's down

 ./check_asterisk_ami8 -H localhost -u MonitorUser -p MonitorPass -q calls -w 0:5 -c 0:8
   Check the active calls, raise warning if more than 5 calls are in progress, raise critical if more than 8 are in progress

 ./check_asterisk_ami8 -H localhost -u MonitorUser -p MonitorPass -q channels -w 0:7 -c 0:10
   Check the active channels, raise warning if more than 7 channels are in use, raise critical if more than 10 channels are in use

 ./check_asterisk_ami8 -H localhost -u MonitorUser -p MonitorPass -q allpeers -W -C les.net,pots1 -w 4:5 -c 2:6
   Check all peers
   If les.net or post1 is down raise Critical.
   A warning is NOT generated if other peers are offline (someone unplugs a handset)... however:
      If the total online is outside 4-5 raise Warning
       If the total online is outside 2-6 raise Critical
   So if we have LOTS of handsets offline, let's take a look.... 
