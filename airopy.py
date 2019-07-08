# script based on  https://charlesreid1.com/wiki/Scapy/Airodump_Clone  and https://github.com/DanMcInerney/wifijammer/blob/master/wifijammer
# Running on Python3 
# Author: @JosueEncinar

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
import os
import sys
import time
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import socket
import struct
import fcntl
import re
import requests
import argparse
from mac_vendors import macs
from custom_print import print_err, print_i, print_ok


class Sniffing:
    def __init__(self, iface=None, channel=None, accesspoint=None, america=False, maximum=None, noupdate=None, show_stations=True, show_aps=True, filter_macs=None):
        self.show_stations = show_stations
        self.show_aps = show_aps
        if accesspoint:
            accesspoint = accesspoint.upper()
        self.args = {
            "interface": iface,
            "channel": channel,
            "maximum": maximum,
            "noupdate": noupdate,
            "accesspoint": accesspoint,
            "america": america
            }
        self.clients_aps = []
        self.aps = []
        self.DN = open(os.devnull, 'w')
        self.lock = Lock()
        self.monitor_on = False
        self.mon_iface = self.get_mon_iface(self.args["interface"])
        conf.iface = self.mon_iface
        self.mon_mac = self.get_mon_mac(self.mon_iface)
        self.monchannel = 1
        self.filter_macs = filter_macs
        self.exit = False

    ########################################
    # Begin interface settings
    ########################################

    def get_mon_iface(self, iface):
        if iface:
            if self.check_monitor(iface):
                self.monitor_on = True
                return iface
        monitors, interfaces = self.iwconfig()
        if len(monitors) > 0:
            self.monitor_on = True
            return monitors[0]
        else:
            # Start monitor mode on a wireless interface
            print_ok('Finding the most powerful interface...')
            interface = self.get_iface(interfaces)
            monmode = self.start_mon_mode(interface)
            return monmode

    def check_monitor(self, iface):
        try:   
            proc = Popen(['iwconfig', iface], stdout=PIPE, stderr=PIPE)
            data =  proc.communicate()
            if "Mode:Monitor" in data[0].decode():
                return True
            elif "No such device" in data[1].decode():
                print_err("Interface not found")
                return False
            print_i("Interface is not in mode monitor")
            self.start_mon_mode(iface)
            return True
        except OSError:
            print_err('Could not execute "iwconfig"')
            return False

    def iwconfig(self):
        monitors = []
        interfaces = {}
        try:
            proc = Popen(['iwconfig'], stdout=PIPE, stderr=self.DN)
        except OSError:
            print_err('Could not execute "iwconfig"')
            self.exit = True
            return
        for line in proc.communicate()[0].decode().split('\n'):
            if len(line) == 0: continue # Isn't an empty string
            if line[0] != ' ': # Doesn't start with space
                wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
                if not wired_search: # Isn't wired
                    iface = line[:line.find(' ')] # is the interface
                    if 'Mode:Monitor' in line:
                        monitors.append(iface)
                    elif 'IEEE 802.11' in line:
                        if "ESSID:\"" in line:
                            interfaces[iface] = 1
                        else:
                            interfaces[iface] = 0
        return monitors, interfaces


    def get_iface(self, interfaces):
        scanned_aps = []
        if len(interfaces) < 1:
            print_err('No wireless interfaces found, bring one up and try again')
            self.exit = True
            return None
        if len(interfaces) == 1:
            for interface in interfaces:
                return interface

        # Find most powerful interface
        for iface in interfaces:
            count = 0
            proc = Popen(['iwlist', iface, 'scan'], stdout=PIPE, stderr=self.DN)
            for line in proc.communicate()[0].decode().split('\n'):
                if ' - Address:' in line: # first line in iwlist scan for a new AP
                    count += 1
            scanned_aps.append((count, iface))
            print_ok(f'Networks discovered by {iface}: {count}')
        try:
            interface = max(scanned_aps)[1]
            return interface
        except Exception as e:
            print_err(f'Minor error: {e}')
            iface = interfaces[0]            
            print_i(f'    Starting monitor mode on {iface}')
            return iface

    def start_mon_mode(self, interface):
        print_ok(f'Starting monitor mode off {interface}')
        try:
            os.system('ifconfig %s down' % interface)
            os.system('iwconfig %s mode monitor' % interface)
            os.system('ifconfig %s up' % interface)
            return interface
        except Exception:
            print_err('Could not start monitor mode')
            self.exit = True

    def remove_mon_iface(self, mon_iface):
        os.system('ifconfig %s down' % mon_iface)
        os.system('iwconfig %s mode managed' % mon_iface)
        os.system('ifconfig %s up' % mon_iface)

    def get_mon_mac(self, mon_iface):
        '''
        http://stackoverflow.com/questions/159137/getting-mac-address
        '''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  mon_iface[:15])
        mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
        print_ok(f'Monitor mode: {mon_iface} - {mac}')
        return mac

    ########################################
    # End interface settings
    ########################################

    ########################################
    # Set channel hop behavior
    ########################################


    def channel_hop(self, mon_iface, args):
        channel_num = 0
        max_channel = 11 if args["america"] else 13
        err = None

        while True:
            if args['channel']:
                with self.lock:
                    self.monchannel = args['channel']
            else:
                channel_num +=1
                if channel_num > max_channel:
                    channel_num = 1
                with self.lock:
                    self.monchannel = str(channel_num)

            try:
                proc = Popen(['iw', 'dev', mon_iface, 'set', 'channel', self.monchannel], stdout=self.DN, stderr=PIPE)
                for line in proc.communicate()[1].decode().split('\n'):
                    if len(line) > 2: # iw dev shouldnt display output unless there's an error
                        err = f'Channel hopping failed: {line}'
                if self.exit:
                    return
                self.output(err, self.monchannel)
                time.sleep(1)
            except OSError:
                print_err('Could not execute "iw"')
                self.exit = True
                return
            
    ########################################
    # End channel hop behavior
    ########################################

    ########################################
    # Set output filtering
    ########################################

    def output(self, err, monchannel):
        os.system('clear')
        if err:
            print_err(err)
        else:
            print_ok(f'{self.mon_iface} channel: {monchannel}\n')
        if len(self.clients_aps) > 0 and self.show_stations:
            print('    ch          Client                        BSSID (ESSID)')
        # Print the clients list
            with self.lock:
                for ca in self.clients_aps:
                    print_i(f"[*] {ca['channel'].ljust(2)} - {ca['client']} ({ca['vendor']}) - {ca['bssid_ap']}  ({ca['essid_ap']})")
        if len(self.aps) > 0 and self.show_aps:
            print('\n      Access Points    Enc  ch   ESSID')
            with self.lock:
                for ap in self.aps:
                    print(f'[*] {ap["bssid"]} - {ap["encrypted"]} - {ap["ap_channel"].ljust(2)} - {ap["ssid"]}')
        print('')

    def noise_filter(self, addr1, addr2):
        # Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
        ignore = ['FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00', '33:33:00:', '33:33:FF:', '01:80:C2:00:00:00', '01:00:5E:']

        for i in ignore:
            if i in addr1 or i in addr2:
                return True
        return False
    ########################################
    # End output filtering
    ########################################

    ########################################
    # Set packet handling 
    ########################################

    def cb(self, pkt):
        '''
        Look for dot11fcs packets that aren't to or from broadcast address,
        are type 1 or 2 (control, data), and append the addr1 and addr2
        to the list of clients
        '''
        # return these if's keeping self.clients_self.aps the same or just reset self.clients_self.aps?
        # I like the idea of the tool repopulating the variable more
        if self.args['maximum']:
            if self.args['noupdate']:
                if len(self.clients_aps) > int(self.args['maximum']):
                    return
            else:
                if len(self.clients_aps) > int(self.args['maximum']):
                    with self.lock:
                        self.clients_aps = []
                        self.aps = []

        # We're adding the AP and channel to the clients list at time of creation rather
        # than updating on the fly in order to avoid costly for loops that require a self.lock
        if pkt.haslayer(Dot11FCS):
            if pkt.addr1 and pkt.addr2:
                # Filter out all other self.aps and clients if asked
                addr1 = pkt.addr1.upper()
                addr2 = pkt.addr2.upper()
                if self.args['accesspoint'] and self.args['accesspoint'] not in [addr1, addr2]:
                    return

                 # Ignore all the noisy packets like spanning tree
                if self.noise_filter(addr1, addr2):
                    return

                if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                    privacy = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                    {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
            
                    # Check for encrypted networks
                    encrypted = "Y" if re.search("privacy", privacy) else "N"

                    self.aps_add(pkt, self.args['channel'], self.args["america"], encrypted)

                # Management = 1, data = 2 // If you want to see the stations
                if pkt.type in [1, 2] and self.show_stations:
                    self.clients_aps_add(addr1, addr2)

    def aps_add(self, pkt, chan_arg, world_arg, enc):
        ssid       = pkt[Dot11Elt].info
        bssid      = pkt[Dot11FCS].addr3.upper()
        try:
            # Thanks to airoscapy for below
            ap_channel = ord(pkt[Dot11Elt:3].info)
            chans = list(range(1,12)) 
            if  not self.args["america"]: 
                chans.extend([12, 13])
            if ap_channel not in chans:
                return
            if chan_arg and (ap_channel != chan_arg):
                return
        except:
            return

        # Check if it's added to our AP list
        if len(self.aps):
            for b in self.aps:
                if bssid == b["bssid"]:
                    return

        with self.lock:
            self.aps.append({
                    "bssid": bssid.upper(), 
                    "ap_channel": str(ap_channel), 
                    "ssid": ssid.decode(),
                    "encrypted": enc})

    def clients_aps_add(self, addr1, addr2):
        data = {}
        for ca in self.clients_aps:
            cl = ca["client"]
            if addr1 == cl or addr2 == cl:   
                return

        if len(self.aps) > 0:
            data = None
            for ap in self.aps:
                addr = None
                ap_bssid = ap["bssid"]
                if ap_bssid == addr1:
                    addr = addr2
                elif ap_bssid == addr2:
                    addr = addr1
                
                if addr:
                    data = {
                        "client": addr,
                        "bssid_ap": ap["bssid"],
                        "essid_ap": ap["ssid"],
                        "channel": ap["ap_channel"],
                        "vendor": ""
                    }
                    # Free API - 1000 requests per day (Get mac vendor)
                    response = requests.get("https://api.macvendors.com/"+addr)
                    if response.status_code == 200:
                        data["vendor"] = response.text[0:12]
                        
                    fill = 12 - len(data["vendor"])
                    if fill > 0:
                        data["vendor"] = data["vendor"] + " "*fill
                    do_it = True
                    if self.filter_macs:
                        do_it = False
                        for m in self.filter_macs:
                            if addr.startswith(m):
                                do_it = True
                    if do_it:
                        with self.lock:
                            self.clients_aps.append(data)
                    
    def stop(self, event, frame):
        self.exit = True
        if not self.monitor_on:
            self.remove_mon_iface(self.mon_iface)
            os.system('service network-manager restart')
        print("")
        print_err('Closing')

    ########################################
    # End packet handling 
    ########################################

    ########################################
    # Run
    ########################################
    def start_sniffing(self):
        # Start channel hopping
        th = Thread(target=self.channel_hop, args=(self.mon_iface, self.args))
        th.daemon = True
        th.start()
        signal(SIGINT, self.stop)
        sniff(iface=self.mon_iface, store=0, prn=self.cb, stop_filter=self.exit_or_not)

    def exit_or_not(self, pkt):
        if self.exit:
            return True
        return False


########################################
# Test
########################################

if __name__ == "__main__":
    if os.geteuid():
        print_err("Please run as root")     
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--iface", help="Specify interface")
        parser.add_argument("-c", "--channel", help="If you want to fix a channel")
        parser.add_argument("-a", "--america", help="Set this flag if you are in America (11 channels)",  action='store_true')
        parser.add_argument("-ap", "--aps", help="Set this flag if you don't want check aps",  action='store_true')
        parser.add_argument("-s", "--stations", help="Set this flag if you don't want check stations",  action='store_true')
        parser.add_argument("-d", "--device", help="Filter Macs (0-Google / 1-Apple/ 2-Microsoft/ 3-Samsung/ 4-Huawei/ 5-LG/ 6-Xiaomi/ 7-Intel)")
        args = parser.parse_args()
        iface = None
        channel = None

        if args.iface:
            iface = args.iface
        if args.channel: 
            channel = args.channel
        if args.america:
            america = True
        macs_select = None
        try:
            macs_select = macs[args.d]["macs"]
        except:
            pass
        if not (args.aps or args.stations):
            print_err("Neither stations (-s) nor access points (-ap) have been chosen")
        else:
            sn = Sniffing(iface=iface, channel=channel, america=args.america, show_aps=args.aps, show_stations=args.stations, filter_macs=macs_select)
            sn.start_sniffing()