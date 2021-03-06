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
from daemon import Daemon


# some globals (for now)
# initialize the dictionary for statistics
stats = {'total_pkts_in':0,        # total number of packets captured
        'non_arp_pkts_in':0,      # number of non-arp packets captured (ignored)
        'arp_requests_in':0,      # number of arp request packets captured
        'arp_replies_in':0,       # number of arp reply packets captured (ignored)
        'arp_response_out':0      # number of arp responses we've sent
        }

# this is the dictionary that defines the hosts we'll send an
#   arp resonse for (mostly these are esp8266s)
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
            "192.168.1.241" : "EC:FA:BC:91:A8:35",
            "192.168.1.242" : "DC:4F:22:20:8A:0F",
            "192.168.1.243" : "84:F3:EB:22:83:4F",
            "192.168.1.244" : "80:7D:3A:7A:8A:70",
            "192.168.1.245" : "84:F3:EB:22:D8:04",
            "192.168.1.246" : "84:F3:EB:67:CA:A5",
            "192.168.1.247" : "B4:E6:2D:54:61:EB",
            "192.168.1.248" : "BC:DD:C2:14:E3:38",
            "192.168.1.249" : "cc:50:e3:14:3d:ca"
            }

class my_daemon(Daemon):
    def receive_signal(self, signum, stack):
        """ Signal processor. """
        if signum == signal.SIGHUP:
            # we received a HUP, let's exit
            print('SIGHUP received -- restarting')
            self.restart()
        elif signum == signal.SIGUSR1:
            self.dump_stat()
        elif signum == signal.SIGUSR2:
            self.dump_mac_dictionary()
        elif signum == signal.SIGQUIT:
            self.stop()
        elif signum == signal.SIGTERM:
            message = 'unceremoniously terminating'
            config['logger'].info(message)
            sys.exit(1)
        else:
            # process any other signals as an exercise
            message = 'received signal {}'.format(signum)
            config['logger'].info(message)


    def dump_stat(self):
        """ Dump statistics about what we've been doing. """
        message = ', '.join("{!s}={!r}".format(key, val) for (key, val) in sorted(stats.items()))
        config['logger'].info(message)
        return


    def dump_mac_dictionary(self):
        """ Dump the mac dictionary. """
        message = ', '.join("{!s}={!s}".format(key, val) for (key, val) in sorted(mac_dict.items()))
        config['logger'].info(message)
        return


    def run(self):
        pass


def eth_ntos(mac):
    """ convert a 6 byte field to a human readable mac address """
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ((mac[0]),
                                           (mac[1]),
                                           (mac[2]),
                                           (mac[3]),
                                           (mac[4]),
                                           (mac[5]))


def eth_ston(smac):
    """ convert a mac string to a packed 6B """
    mac = smac.split(':')
    ret = struct.pack('x')

    ret = struct.pack('!6B',
                    int(mac[0], 16),
                    int(mac[1], 16),
                    int(mac[2], 16),
                    int(mac[3], 16),
                    int(mac[4], 16),
                    int(mac[5], 16)
    )

    return ret


def decode_eth(eth_data):
    """ decode the ethernet header data """
    return struct.unpack('!6s6sH', eth_data)
    

def decode_arp(arp_data):
    """ decode the arp data from the packet """
    #print('a', struct.unpack('!HHBBH6B4s6s4s', arp_data))
    return struct.unpack('!HHBBH6s4s6s4s', arp_data)


def build_arp_packet(sender_mac, sender_ip, target_mac, target_ip):
    arp_packet = [
        struct.pack('!H', 0x0001), # hw type (0x1 == ethernet)
        struct.pack('!H', 0x0800), # proto (0x0800 == ipv4)
        struct.pack('!B', 0x06), # hw size
        struct.pack('!B', 0x04), # proto size
        struct.pack('!H', 0x0002), # opcode
        struct.pack('!6B', *(eth_ston(sender_mac))), # sender hw addr (mac)
        struct.pack('!4B', *socket.inet_aton(sender_ip)), # sender proto addr (ip)
        struct.pack('!6B', *(0x00,)*6), # target hw addr (mac)
        struct.pack('!4B', *socket.inet_aton(target_ip)) # target proto addr (mac)
    ]
    #print(arp_packet)
    return arp_packet


def send_arp_packet(sender_mac, sender_ip, target_mac, target_ip,
                    src_mac, broadcast_reply=False):
    """ send an arp packet to respond to the arp request """
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('wlan0', 0))
    
    #print('aa=', target_mac, sender_mac, my_mac, ARP)
    if broadcast_reply:
        eth_hdr = struct.pack("!6s6sH", eth_ston('FF:FF:FF:FF:FF:FF'),
                              eth_ston(src_mac), 0x0806)
    else:
        eth_hdr = struct.pack("!6s6sH", eth_ston(sender_mac),
                              eth_ston(src_mac), 0x0806)
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
    sock.send(packet)
    stats['arp_response_out'] += 1

    # this will ensure the GC frees this up
    sock.close()


def arp_request(target_ip, sender_ip):
    """ we have an arp request, do we respond? """
    #print('%s is asking about %s' % (sender_ip, target_ip))
    if target_ip in mac_dict:
        message = '{} asked about {}, sending reponse'.format(sender_ip, target_ip)
        config['logger'].info(message)
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
    """ let's print out some statistics we kept while running """
    message = ', '.join("{!s}={!r}".format(key, val) for (key, val) in sorted(stats.items()))
    config['logger'].info(message)

    return
        
def get_program_name():
    """ strip out the basefilename """
    # get the base filename
    progname = os.path.splitext((sys.argv[0]))[0]
    
    # but if we started with ./ remove it
    if progname[0:2] == './':
        progname = progname[2:]
        
    return progname

def get_logfile(progname):
    logfile = None
    logfile = progname + '.log'
    return logfile


def check_devices(interface):
    devices = pcapy.findalldevs()
    if interface not in devices:
        return False
    
    return True


def logging_add_foreground(config):
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s",
                                  "%Y-%m-%d %H:%M:%S")

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    config['logger'].addHandler(console_handler)
    
    return


def setup_logging(config):
    """ define how we want to log things """
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                                  "%Y-%m-%d %H:%M:%S")

    # create a file handler
    file_handler = TimedRotatingFileHandler(config['logfile'], when='midnight')
    file_handler.setFormatter(formatter)

    # create the logger object
    logger = logging.getLogger(config['progname'])
    logger.setLevel(logging.DEBUG)

    # attach the handlers
    logger.addHandler(file_handler)

    return logger


def runSniffer(config):
    """ run the sniffer """
    SNAPLEN = 2048 # how big of a packet do we want to capture? 
    ARP = 1544 # (0x0806) this is the protocol number in decimal
    lastnow = 0

    # this is the capture object
    #   in hindsight i could have filtered for arp, but what fun is that?
    cap = pcapy.open_live(config['interface'], SNAPLEN, 1, 0)

    # the big bad loop
    try:
        while True:
            now = int(time.time())
            # do we want to print stats at all?
            if config['stat_interval'] > 0:
                # make sure we don't catch all the microseconds of now
                if now != lastnow:
                    # is this our interval?
                    if now % config['stat_interval'] == 0: # every 60 seconds emit stats
                        print_statistics()
                        lastnow = now

            (header, packet) = cap.next()
            stats['total_pkts_in'] += 1
            # this is the length of the ethernet header
            eth_length = 14
            arp_length = 28
            
            # this is the ethernet header
            eth_header = packet[:eth_length]
            eth = decode_eth(eth_header)
            eth_protocol = socket.ntohs(eth[2]) # proto
            dst = eth_ntos(packet[0:6]) # dmac
            src = eth_ntos(packet[6:12]) # smac
            
            # arp packets only please
            if eth_protocol != ARP:
                stats['non_arp_pkts_in'] += 1
                continue
            else:
                # this is the arp protocol data
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
                        send_arp_packet(sender_mac, sender_ip, target_mac, target_ip,
                                        config['my_mac'], config['broadcast_reply'])
                elif arp_data[4] == 2: # arp reply, we aren't doing anything with these
                    arp_reply()
                else:
                    pass

    except KeyboardInterrupt:
        print_statistics()
        sys.exit(0)

def create_parser(config):
    # setup a few predetermined values
    config['stat_interval'] = 60
    config['pidfile'] = '/tmp/' + config['progname'] + '.pid'

    # build the parser
    parser = argparse.ArgumentParser(description='aaron\'s arp responder (aar)')
    parser.add_argument('cmd', choices=['restart', 'start', 'stop', 'status', 'help'])
    parser.add_argument('--pid', dest='pid', action='store',
                        default=config['pidfile'],
                        help='pid file (default: /tmp/' + config['progname'] + '.pid)')
    parser.add_argument('--logfile', dest='logfile', action='store',
                        default=config['logfile'],
                        help='log file (default: ' + config['progname'] + '.log)')
    parser.add_argument('-i', '--int', action='store',
                        default=config['interface'],
                        help='interface to listen on (default: ' + config['interface'] + ')')
    parser.add_argument('-s', '--stat-interval', action='store',
                        default=60,
                        help='statistics logging interval (default: ' + str(config['stat_interval']) + ')')
    parser.add_argument('-fg', '--foreground', action='store_true',
                        default=False,
                        help='run in the foreground (default: False)')
    parser.add_argument('-br', '--broadcast', action='store_true',
                        default=False,
                        help='broadcast arp responses (default: False)')
    return parser


def handle_args(args, config):
    """ process the arguments """
    # did we get anything useful?
    
    config['pidfile']  = args.pid
    config['interface'] = args.int
    config['foreground'] = args.foreground
    config['logfile'] = args.logfile
    config['broadcast_reply'] = args.broadcast
    config['stat_interval'] = args.stat_interval
    return


def main(config):
    """ this is the main() entry point """

    # argument handling
    parser = create_parser(config)
    args = parser.parse_args()
    handle_args(args, config)

    # check the device to make sure it exists
    if not check_devices(config['interface']):
        print('{} is not a valid device.'.format(config['interface']))
        sys.exit(1)

    # are we running in the foregound?
    if config['foreground']:
        logging_add_foreground(config)

    # get the command
    cmd = args.cmd
    
    # instintate a daemon object
    daemon = my_daemon(config)

    # the various commands to control the daemon
    if cmd == 'start':
        if not config['foreground']:
            pid = daemon.start()
            config['logger'].debug('starting daemon')
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
    
    config['logger'].info('starting sniffer')
    runSniffer(config)

if __name__ == "__main__":
    # make sure we are using python3
    if sys.version_info[0] < 3:
        print('python3 must be used')
        sys.exit(1)

    # we use the pcapy module (https://www.secureauth.com/labs/open-source-tools/pcapy)
    # the pcapy module requires libpcap-dev or libpcap-devel installed
    modulename = 'pcapy'
    if modulename not in sys.modules:
        print('You have not imported the {} module'.format(modulename))
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
    config = {}
    config['progname'] = get_program_name() # correct progran name
    config['logfile'] = get_logfile(config['progname']) # default log filename
    config['interface'] = 'wlan0' # interface to use
    config['logger'] = setup_logging(config)
    # get our mac address
    config['my_mac'] = netifaces.ifaddresses('wlan0')[netifaces.AF_LINK][0]['addr']
    
    main(config)
