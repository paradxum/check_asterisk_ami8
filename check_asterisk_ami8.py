#!/usr/bin/python
import os,re,sys,socket
from optparse import OptionParser

__author__ = "Eric Schultz <eric.schultz@cyvon.com>"
__version__ = "1.00"

# Concept and ami interface taken from:
# check_asterisk_ami by Jason Rivers <jason@jasonrivers.co.uk>
# check_asterisk_ami_v2 by Deraoui Said <said.deraoui@keysource.be>
#
#
# Quick note --
#  AMI Interface must be enabled (in manager.conf), firewall cannot be blocking AMI port (default: 5038)
#  For Freepbx you can add something like this to manager_custom.conf
#[MonitorUser]
#secret = MonitorPass
#writetimeout = 500
#read = command
#
# But PLEASE change the user/password
#
# Examples:
# ./check_asterisk_ami8 -H localhost -u MonitorUser -p MonitorPass -q pjsippeers
#   Check all pjsippeers, raise Critical if any are Down
#
# ./check_asterisk_ami8 -H localhost -u MonitorUser -p MonitorPass -q sippeers -I -i pots1
#   Check the sip peer pots1 and rais Critical if it's down
#
# ./check_asterisk_ami8 -H localhost -u MonitorUser -p MonitorPass -q calls -w 0:5 -c 0:8
#   Check the active calls, raise warning if more than 5 calls are in progress, raise critical if more than 8 are in progress
#
# ./check_asterisk_ami8 -H localhost -u MonitorUser -p MonitorPass -q channels -w 0:7 -c 0:10
#   Check the active channels, raise warning if more than 7 channels are in use, raise critical if more than 10 channels are in use
#
# ./check_asterisk_ami8 -H localhost -u MonitorUser -p MonitorPass -q allpeers -W -C les.net,pots1 -w 4:5 -c 2:6
#   Check all peers
#   If les.net or post1 is down raise Critical.
#   A warning is NOT generated if other peers are offline (someone unplugs a handset)... however:
#      If the total online is outside 4-5 raise Warning
#       If the total online is outside 2-6 raise Critical
#   So if we have LOTS of handsets offline, let's take a look.... 

#Handle Arguments
def csv_callback(options, opt, value, parser):
    setattr(parser.values, options.dest, value.split(','))

def pass_args(args):
	usage = "usage: %prog [options]"
	version = "%%prog %s"%__version__
	parser = OptionParser(usage=usage,version=version)
	parser.add_option("-H","--host",default="localhost",help="Asterisk host ip/name")
        parser.add_option("-P","--ami_port",type=int,default=5038,help="Asterisk AMI port (default: 5038)")
	parser.add_option("-u","--ami_user",help="AMI username")
	parser.add_option("-p","--ami_pass",help="AMI secret/password")

	parser.add_option("-q","--query",type="choice",choices=["calls","channels","pjsippeers","sippeers","iaxpeers","allpeers"],default='allpeers',help="Query (calls, channels, pjsippeers, sippeers, iaxpeers, allpeers)")
	
        parser.add_option("-I","--ignore",action="store_true",dest='ignore',default=False,help="Ignore all Channels not specifically included")
        parser.add_option("-i","--include",type="string",action="callback",callback=csv_callback,help="Specifically Include these channels (csv)")
        parser.add_option("-x","--exclude",type="string",action="callback",callback=csv_callback,help="Exclude these Channels (csv)")
        
        parser.add_option("-C","--critical_only",type="string",action="callback",callback=csv_callback,help="Only report Critical if these peers are down (csv) others are warnings")
	parser.add_option("-W","--disable_warn",action="store_true",dest='disable_warn',default=False,help="Disables warnings/critical if peers are down")
        
        parser.add_option("-w","--warn_range",help="Warn if outside range (e.g 5:6 would warn if only 4 or 7 peers online)")
        parser.add_option("-c","--crit_range",help="Critical if outside range (e.g 5:6 would alarm if only 4 or 7 peers online)")
        
	return parser.parse_args(args)
(options,args) = pass_args(sys.argv)

# Set up the asterisk commands
PJSIP_command = "pjsip show endpoints"
SIP_command = "sip show peers"
#SIP_INUSE_command = "sip show inuse all"   -- Tried to use this, doesn't seem to work (always shows 0/0/0) sip inuse count disabled.
IAX2_command = "iax2 show peers"
CALLS_command = "core show channels"    # This gives us both calls and channel count
command = ""
if options.query == "pjsippeers":
    command = PJSIP_command
elif options.query == "sippeers":
    command = SIP_command
elif options.query == "iaxpeers":
    command = IAX2_command
elif options.query in ['calls','channels']:
    command = CALLS_command
# query "allpeers" is special

def run_command(s,command):
    s.send("Action: Command\r\ncommand: %s\r\n\r\n"%command)
    rstr = ""
    while 1:
        data = s.recv(4096)
        if not data: break
        rstr += data
        if re.search("--END COMMAND--",data): break
    return rstr

def check_for_asterisk_error(rstr):
    if re.search("Response: Error",rstr):
        res = re.search("Message: (.+)",rstr)
        if res:
            print "Asterisk CRITICAL: Error: %s"%res.group(1)
            sys.exit(2)
        else:
            print "Asterisk CRITICAL: Error in response"
            sys.exit(2)


# Talk to Asterisk and get our data
try:
    s = socket.socket()
    s.connect((options.host,options.ami_port))
    s.send("Action: login\r\nUsername: %s\r\nSecret: %s\r\nEvents: off\r\n\r\n"%(options.ami_user,options.ami_pass))
    if options.query == "allpeers":
        rstr = run_command(s,PJSIP_command)
        check_for_asterisk_error(rstr)
        rstr_pjsip = rstr
        rstr = run_command(s,SIP_command)
        check_for_asterisk_error(rstr)
        rstr_sip = rstr
        rstr = run_command(s,IAX2_command)
        check_for_asterisk_error(rstr)
        rstr_iax = rstr
    else:
        rstr = run_command(s,command)
        check_for_asterisk_error(rstr)
    s.send("Action: Logoff\r\n\r\n")
except:
	print "Asterisk CRITICAL: Connection Error"
        sys.exit(2)

#print rstr
#sys.exit(0)

# Subroutines for parsing the individual results
def parse_pjsippeers(rstr):
    peers = {}
    in_peer = ""
    for l in rstr.splitlines():
        pre = re.search("Endpoint:\s+(.+?)(\/.*?|)\s+(In use|Not in use|Unavailable)",l)
        if pre:
            in_peer = pre.group(1)
            peers[in_peer] = {}
            peers[in_peer]['status'] = pre.group(3)
            peers[in_peer]['registered'] = False
            continue
        if in_peer != "" :
            if re.search("Contact:\s+.* Avail",l):
                peers[in_peer]['registered'] = True
    return peers

def parse_sippeers(rstr):
    peers = {}
    for l in rstr.splitlines():
        if re.search(":",l):
            continue
        pre = re.search("^(.*?)\s+(.*)\s+(OK|Unmonitored)",l)
        if pre:
            in_peer = pre.group(1)
            peers[in_peer] = {}
            peers[in_peer]['status'] = "Not in use"
            peers[in_peer]['registered'] = False
            if pre.group(3) == "OK":
                peers[in_peer]['registered'] = True
    return peers

def parse_iaxpeers(rstr):
    peers = {}
    for l in rstr.splitlines():
        if re.search(":",l):
            continue
        pre = re.search("^(.*?)\s+(.*)\s+(OK|UNKNOWN)",l)
        if pre:
            in_peer = pre.group(1)
            peers[in_peer] = {}
            peers[in_peer]['status'] = "Not in use"
            peers[in_peer]['registered'] = False
            if pre.group(3) == "OK":
                peers[in_peer]['registered'] = True
    return peers

def parse_calls(rstr):
    channels = 0
    calls = 0
    totalcalls = 0
    for l in rstr.splitlines():
        pre = re.search("^(\d+)\s+active channels",l)
        if pre:
            channels = pre.group(1)
            continue
        pre = re.search("^(\d+)\s+active calls",l)
        if pre:
            calls = pre.group(1)
            continue
        pre = re.search("^(\d+)\s+calls processed",l)
        if pre:
            totalcalls = pre.group(1)
            continue
    return (channels,calls,totalcalls)

# Parse out the results
peers = {}
if options.query == "pjsippeers":
    peers = parse_pjsippeers(rstr)
elif options.query == "sippeers":
    peers = parse_sippeers(rstr)
elif options.query == "iaxpeers":
    peers = parse_iaxpeers(rstr)
elif options.query in ['calls','channels']:
    (channels,calls,totalcalls) = parse_calls(rstr)
elif options.query == "allpeers":
    peers = parse_pjsippeers(rstr_pjsip)
    peers.update(parse_sippeers(rstr_sip))
    peers.update(parse_iaxpeers(rstr_iax))
    

ret_val=0
ret_str=""
# parse the peers data structure and raise alarms if needed.
peers_up = 0
peers_down = 0
peers_inuse = 0
for p in peers:
    is_up = False
    if not peers[p]['registered']:
        peers_down+=1
    elif peers[p]['status'] == "In use":
        is_up = True
        peers_up+=1
        peers_inuse+=1
    elif peers[p]['status'] == "Not in use":
        is_up = True
        peers_up+=1
    else:
        peers_down+=1

    # If a peer is up, there's nothing to do, so just move on
    if is_up:
        continue

    # peers are included in counts even if excluded
    if p == "anonymous" or (options.exclude and p in options.exclude):
        continue
    if options.ignore and options.include and p not in options.include:
        continue

    # OK, so the peer is down, it's not anonymous, so we need to determine if we alert and what level
    if options.critical_only:
        if p in options.critical_only:
            ret_val = 2
            ret_str += "Crit Peer %s Offline, "%p
        elif options.disable_warn:
            pass
        else:
            if ret_val < 1:
                ret_val = 1
            ret_str += "Warn Peer %s Offline, "%p

    elif options.disable_warn:
        pass
    else:
        ret_val = 2
        ret_str += "Crit Peer %s Offline, "%p

# if we used the include or critical only and a peer is missing... do something
if options.critical_only:
    for p in options.critical_only:
        if p not in peers:
            ret_val = 2
            ret_str += "Crit Peer missing %s, "%p
if options.include:
    for p in options.include:
        if p not in peers:
            ret_val = 2
            ret_str += "Crit Peer missing %s, "%p

# Check our counts and raise the warning level if needed
def in_range(crange,value):
    (l,h) = crange.split(':')
    if int(value) >= int(l) and int(value) <= int(h):
        return True
    return False
if options.query == "calls":
    if options.crit_range and not in_range(options.crit_range,calls):
        ret_val = 2
        ret_str += "Crit Calls %s"%peers_up
    elif options.warn_range and not in_range(options.warn_range,calls):
        ret_val = 1
        ret_str += "Warn Calls %s"%peers_up
    status = "Calls: %s Channels: %s Total Calls: %s "%(calls,channels,totalcalls)
elif options.query == "channels":
    if options.crit_range and not in_range(options.crit_range,channels):
        ret_val = 2
        ret_str += "Crit Channels %s"%peers_up
    elif options.warn_range and not in_range(options.warn_range,channels):
        ret_val = 1
        ret_str += "Warn Channels %s"%peers_up
    status = "Calls: %s Channels: %s Total Calls: %s "%(calls,channels,totalcalls)
else:
    if options.crit_range and not in_range(options.crit_range,peers_up):
        ret_val = 2
        ret_str += "Crit Peers up %s"%peers_up
    elif options.warn_range and not in_range(options.warn_range,peers_up):
        ret_val = 1
        ret_str += "Warn Peers up %s"%peers_up
    status = "In-Use: %s Up: %s Down: %s "%(peers_inuse,peers_up,peers_down)


if ret_str == "":
    ret_str = status
else:
    ret_str = "%s -- %s"%(status,ret_str)

if ret_val == 0:
	print "Asterisk OK: %s"%ret_str
elif ret_val == 1:
	print "Asterisk WARNING: %s"%ret_str
elif ret_val == 2:
	print "Asterisk CRITICAL: %s"%ret_str
sys.exit(ret_val)

