#!/usr/bin/env python3

import argparse
import netifaces
import os
import pcapy
import pwd
import signal
import socket
import struct
import sys
import time
import logging
from logging.handlers import TimedRotatingFileHandler
from daemon import daemon


# some globals (for now)


# get our mac address
my_mac = netifaces.ifaddresses('wlan0')[netifaces.AF_LINK][0]['addr']

# initialize the dictionary for statistics
stats = {'total_pkts_in':0,        # total number of packets captured
        'non_arp_pkts_in':0,      # number of non-arp packets captured (ignored)
        'arp_requests_in':0,      # number of arp request packets captured
        'arp_replies_in':0,       # number of arp reply packets captured (ignored)
        'arp_response_out':0      # number of arp responses we've sent
}

# this is the dictionary that defines  the hosts we'll send an
#   arp resonse for
mac_dict = {#"192.168.1.1" : " 4c:ed:fb:ab:d9:48",
            "192.168.1.20" : "44:61:32:F5:24:0B",
            "192.168.1.21" : "44:61:32:E5:00:47",
            "192.168.1.22" : "44:61:32:D0:71:94",
            "192.168.1.101" : "B8:27:EB:EE:AA:F5",
            "192.168.1.102" : "B8:27:EB:9E:16:AD",
            "192.168.1.133" : "80:7D:3A:76:F4:B4",
            "192.168.1.135" : "84:0D:8E:96:0F:D5",
            "192.168.1.221" : "B4:E6:2D:23:C6:80",
            "192.168.1.224" : "B4:E6:2D:0A:A8:89",
            "192.168.1.249" : "cc:50:e3:14:3d:ca",
            "192.168.1.248" : "BC:DD:C2:14:E3:38",
            "192.168.1.247" : "B4:E6:2D:54:61:EB",
            "192.168.1.246" : "84:F3:EB:67:CA:A5",
            "192.168.1.245" : "84:F3:EB:22:D8:04",
            "192.168.1.244" : "80:7D:3A:7A:8A:70",
            "192.168.1.243" : "84:F3:EB:22:83:4F",
            "192.168.1.242" : "DC:4F:22:20:8A:0F",
            "192.168.1.241" : "EC:FA:BC:91:A8:35"
}

class mydaemon(daemon):
    def receive_signal(self, signum, stack):
        # we received a HUP, let's exit
        if signum == signal.SIGHUP:
            print('SIGHUP received -- restarting')
            self.restart()
        elif signum == signal.SIGUSR1:
            self.dump_stat()
        elif signum == signal.SIGUSR2:
            self.dump_mac_dictionary()
        elif signum == signal.SIGTERM:
            print('SIGTERM received')
            sys.exit(0)
        else:
            # process other signals as an exercise
            print('received signal %d\n' % signum)


    def dump_stat(self):
        message = ', '.join("{!s}={!r}".format(key, val) for (key, val) in sorted(stats.items()))
        logger.info(message)
        return


    def dump_mac_dictionary(self):
        message = ', '.join("{!s}={!r}".format(key, val) for (key, val) in sorted(mac_dict.items()))
        logger.info(message)
        return


    def run(self):
        """Overloaded run form the main class"""
        #
        while True:
            time.sleep(1)


def eth_ntos(a):
    """ convert a 6 byte field to a human readable mac address """
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ((a[0]), (a[1]), (a[2]), (a[3]), (a[4]), (a[5]))
    return b


def eth_ston(a):
    """ convert a mac string to a packed 6B """
    b = a.split(':')
    c = struct.pack('x')

    c = struct.pack('!6B',
                    int(b[0], 16),
                    int(b[1], 16),
                    int(b[2], 16),
                    int(b[3], 16),
                    int(b[4], 16),
                    int(b[5], 16)
    )

    return c


def decode_eth(eth_data):
    """ decode the ethernet header data """
    return struct.unpack('!6s6sH', eth_data)
    

def decode_arp(arp_data):
    """ decode the arp data from the packet """
    #print('a', struct.unpack('!HHBBH6B4s6s4s', arp_data))
    return struct.unpack('!HHBBH6s4s6s4s', arp_data)


def build_arp_packet(sender_mac, sender_ip, target_mac, target_ip):
    arp_packet = [
        struct.pack('!H', 0x0001), # HRD
        struct.pack('!H', 0x0800), # PRO
        struct.pack('!B', 0x06), # HLN
        struct.pack('!B', 0x04), # PLN 
        struct.pack('!H', 0x0002), # OP
        struct.pack('!6B', *(eth_ston(sender_mac))), # SHA
        struct.pack('!4B', *socket.inet_aton(sender_ip)), # SPA
        struct.pack('!6B', *(0x00,)*6), # THA
        struct.pack('!4B', *socket.inet_aton(target_ip)) # TPA
    ]
    #print(arp_packet)
    return arp_packet


def send_arp_packet(sender_mac, sender_ip, target_mac, target_ip, broadcast_reply=False):
    """ send an arp packet to respond to the arp request """
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(('wlan0', 0))
    
    #print('aa=', target_mac, sender_mac, my_mac, ARP)
    if broadcast_reply:
        eth_hdr = struct.pack("!6s6sH", eth_ston('FF:FF:FF:FF:FF:FF'),
                              eth_ston(my_mac), 0x0806)
    else:
        eth_hdr = struct.pack("!6s6sH", eth_ston(sender_mac),
                              eth_ston(my_mac), 0x0806)
    #print('  oe=', eth_hdr)
    #arp_pkt = struct.pack("!HHBBH6s4s6s4s", 0x0001, 0x0800, 0x06, 0x04, 0x0002, eth_ston(my_mac), socket.inet_aton(target_ip), eth_ston(sender_mac), socket.inet_aton(sender_ip))
    arp_pkt = struct.pack("!HHBBH6s4s6s4s", 0x0001, 0x0800, 0x06, 0x04, 0x0002,
        eth_ston(mac_dict[target_ip]),
        socket.inet_aton(target_ip),
        eth_ston(sender_mac), 
        socket.inet_aton(sender_ip))
    #print('  oa=', arp_pkt)
    packet = eth_hdr + arp_pkt
    #print(packet)
    s.send(packet)
    stats['arp_response_out'] += 1

    # this will ensure the GC frees this up
    s.close()


def arp_request(target_ip, sender_ip):
    #global logger
    """ we have an arp request, do we respond? """
    #print('%s is asking about %s' % (sender_ip, target_ip))
    if target_ip in mac_dict:
        message = '{} asked about {}, sending reponse'.format(sender_ip, target_ip)
        print(message)
        logger.info(message)
        #print('%s asked about %s, sending a response' % (sender_ip, target_ip))
        return True
    else:
        #print('%s not found' % target_ip)
        return False


def arp_reply():
    """ placeholder for handling arp response packets """
    stats['arp_replies_in'] = stats['arp_replies_in'] + 1
    return


def print_statistics():
    """Let's print out some statistics we kept while running."""
    message = ', '.join("{!s}={!r}".format(key, val) for (key, val) in sorted(stats.items()))
    logger.info(message)

    return
        
def get_program_name():
    # get the base filename
    progname = None
    progname = os.path.splitext((sys.argv[0]))[0]
    
    # but if we started with ./ remove it
    if progname[0:2] == './':
        progname = progname[2:]
        
    return progname

def get_logfile():
    logfile = None
    logfile = progname + '.log'
    return logfile

def setup_logging(logfile, progname, foreground=False):
    """ define how we want to log things """
    formatter = logging.Formatter("%(asctime)s — %(name)s — %(levelname)s — %(message)s",
                                    "%Y-%m-%d %H:%M:%S")

    if foreground:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)

    file_handler = TimedRotatingFileHandler(logfile, when='midnight')
    file_handler.setFormatter(formatter)

    logger = logging.getLogger(progname)
    logger.setLevel(logging.DEBUG)
    if foreground:
        logger.addHandler(console_handler)

    logger.addHandler(file_handler)
    return logger


def runSniffer(interface, broadcast_reply, stat_interval):
    """ run the sniffer """
    SNAPLEN = 2048 # how big of a pcaket do we want to capture? 
    ARP = 1544 # (0x0806) this is the protocol number in decimal
    lastnow = 0

    # this is the capture object
    #   in hindsight i could have filtered for arp, but what fun is that?
    cap = pcapy.open_live(interface, SNAPLEN, 1, 0)

    # the big bad loop
    try:
        while True:
            now = int(time.time())
            # do we want to print stats at all?
            if stat_interval > 0:
                # make sure we don't catch all the microseconds of now
                if now != lastnow:
                    # is this our interval?
                    if now % stat_interval == 0: # every 60 seconds emit stats
                        print_statistics()
                        lastnow = now

            (header, packet) = cap.next()
            # this is the length of the ethernet header
            stats['total_pkts_in'] += 1
            eth_length = 14
            arp_length = 28
            
            eth_header = packet[:eth_length]
            eth = decode_eth(eth_header)
            eth_protocol = socket.ntohs(eth[2])
            dst = eth_ntos(packet[0:6])
            src = eth_ntos(packet[6:12])
            
            # arp packets only please
            if eth_protocol != ARP:
                stats['non_arp_pkts_in'] += 1
                continue
            else:
                #print('arp ', dst, src, eth_protocol) arp  ff:ff:ff:ff:ff:ff f0:81:73:0a:95:fc 1544
                arp_data = decode_arp(packet[eth_length:(arp_length + eth_length)])
                sender_mac = eth_ntos(arp_data[5])
                sender_ip = socket.inet_ntoa(arp_data[6])
                target_mac = eth_ntos(arp_data[7])
                target_ip = socket.inet_ntoa(arp_data[8])
                if arp_data[4] == 1: # arp request
                    stats['arp_requests_in'] = stats['arp_requests_in'] + 1
                    # debugging here
                    #print('who has %s (%s)? tell %s (%s)' % (target_ip, target_mac, sender_ip, sender_mac))
                    #print('  ie=', eth_header)
                    #print('  ia=', packet[eth_length:(arp_length + eth_length)])
                    if arp_request(target_ip, sender_ip):
                        send_arp_packet(sender_mac, sender_ip, target_mac, target_ip, broadcast_reply)
                elif arp_data[4] == 2: # arp reply, we aren't doing anything with these
                    arp_reply()
                else:
                    pass

    except KeyboardInterrupt:
        print_statistics()
        sys.exit(0)

def main(progname, logfile, interface, logger):
    # build up the arguments to feed the parser
    parser = argparse.ArgumentParser(description='aaron\'s arp responder (aar)')
    parser.add_argument('cmd', choices=['restart', 'start', 'stop', 'status', 'help'])
    parser.add_argument('--pid', dest='pid', action='store',
                        default='/tmp/' + progname + '.pid',
                        help='pid file (default: /tmp/' + progname + '.pid)')
    parser.add_argument('--logfile', dest='logfile', action='store',
                        default=progname + '.log',
                        help='log file (default: ' + progname + '.log)')
    parser.add_argument('-i', '--int', action='store',
                        default='wlan0', help='interface to listen on (default: ' + interface + ')')
    parser.add_argument('-s', '--stat-interval', action='store',
                        default=60, help='statistics logging interval (default: ' + str(60) + ')')
    parser.add_argument('-fg', '--foreground', action='store_true',
                        default=False, help='run in the foreground (default: False)')
    parser.add_argument('-br', '--broadcast', action='store_true',
                        default=False, help='broadcast arp responses (default: False)' )

    # did we get anything useful?
    args = parser.parse_args()
    pidfile = args.pid
    cmd = args.cmd
    interface = args.int
    foreground = args.foreground
    logfile = args.logfile
    broadcast_reply = args.broadcast
    stat_interval = args.stat_interval
    
    # instintate a daemon object
    daemon = mydaemon(progname, pidfile, logger, foreground)
    
    # the various commands to control the daemon
    if cmd == 'start':
        if not foreground:
            pid = daemon.start()
            logger.debug('starting daemon')
    elif cmd == 'stop':
        daemon.stop()
        sys.exit(0)
    elif cmd == 'restart':
        daemon.restart()
    elif cmd == 'status':
        daemon.status()
        sys.exit(0)
    elif cmd == 'help':
        parser.print_help()
        sys.exit(0)
    else:
        parser.print_help()
        sys.exit(0)
    
    logger.info('starting sniffer')
    runSniffer(interface, broadcast_reply, stat_interval)

if __name__ == "__main__":
    # make sure we are using python3
    if sys.version_info[0] < 3:
        print('python3 must be used')
        sys.exit(1)

    # we use the pcapy module (https://www.secureauth.com/labs/open-source-tools/pcapy)
    xmodulename = 'pcapy'
    if xmodulename not in sys.modules:
        print('You have not imported the {} module'.format(xmodulename))
        sys.exit(3)

    # since we using raw sockets, we need to run as root
    uid = (pwd.getpwuid(os.getuid()).pw_uid)
    if uid != 0:
        print('must be root to run this')
        sys.exit(1)

    # make sure we have enough arguments
    if len(sys.argv) < 2:
        print('usage: %s start|stop|restart|status|help' % sys.argv[0])
        sys.exit(1)

    # create some 'globals'
    progname = get_program_name() # correct progran name
    logfile = get_logfile() # default log filename
    interface = 'wlan0' # interface to use (should be dynamic)
    logger = setup_logging(logfile, progname)

    main(progname, logfile, interface, logger)
    
