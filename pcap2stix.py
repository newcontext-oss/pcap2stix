#!/usr/local/bin/python3
#
# pcap2stix.py - PCAP conversion and testing tool.
#
# Convert TCP and UDP packets to STIXv2 observables and submit 
# to a locally configured ELK stack or dump to stdout. 
#
# Copyright (C) 2019, 2020 - New Context Services, Inc.
#

##
#
# IMPORTS
#
##

from datetime import datetime
import base64
import calendar
import csv
import decimal
import getopt
import json
import os
import re
import requests
import shlex
import subprocess as sp
import sys
import time
import urllib.parse
import uuid
import pprint
import binascii
import signal

##
#
# GLOBALS
#
##

COUNT = 0 # packet count

#
# CONFIG
#

TSHARK_PATH = ""
#TSHARK_LIVE = "../../../wireshark-build/run/tshark -i %s "
#TSHARK_PCAP = "../../../wireshark-build/run/tshark -r %s "
TSHARK_LIVE = "tshark -i %s "
TSHARK_PCAP = "tshark -r %s "
TSHARK_FIELDS = "-l -T fields -e frame.time -e frame.protocols -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e tcp.payload -e udp.payload -e ip.proto -e tcp.flags -E header=n -E separator=, -E quote=d -E occurrence=f"

#
# CONSTANTS
#

# ether/ip CSV offsets
FRAME_TIME    = 0  #frame.time
FRAME_PROTOS  = 1  #frame.protos
IP_SRC        = 2  #ip.src
IP_DST        = 3  #ip.dst
TCP_SRC_PORT  = 4  #tcp.srcport
TCP_DST_PORT  = 5  #tcp.dstport
UDP_SRC_PORT  = 6  #udp.srcport
UDP_DST_PORT  = 7  #udp.dstport
TCP_PAYLOAD   = 8  #tcp.payload
UDP_PAYLOAD   = 9  #udp.payload
IP_PROTO      = 10  #ip.proto
TCP_FLAGS     = 11  #tcp.flags

# IANA protocol numbers
IANA_TCP      = 6  # 0x06
IANA_UDP      = 17 # 0x11

# Static TLP Marking Definitions
# https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_k5fndj2c7c1k
TLP_MARKINGS  = { 'white': 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
                  'green': 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
                  'amber': 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
                  'red': 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed' }

##
#
# Code
#
##

#
# usage()
#
def usage():
  usage_str = "Usage: pcap2stix.py -i <iface> [-cd]\n"
  usage_str += "Options:\n"
  usage_str += " -i <iface>, --interface=<iface>      - interface to listen on\n"
  usage_str += " -f <filename>, --file=<filename>     - file to process\n"
  usage_str += " -h <hostname>, --hostname=<hostname> - host and port of ELK stack (default)\n"
  usage_str += " -s, --stdout                         - output STIX observables to stdout\n"
  usage_str += " -b, --base64                         - output payload_bin in base64\n"
  usage_str += " -d, --debug                          - limited debugging output\n"
  usage_str += " -u                                   - Use http instead of https (default)\n"
  usage_str += " -t <tlp_level>, --tlp=<tlp_level>    - Set and enable TLP marking\n"

  sys.stdout.write(usage_str)
  sys.stdout.flush()

#
# extract_usecs( tshark_timestamp )
#
# returns tuple( float s/us, timestring without s/us)
#
def extract_usecs( timestamp ):
  #print timestring
  debug_out( "TIMESTAMP: %s" % timestamp )
  mobj = re.match(r'(^\w\w\w [ |\d]\d, \d\d\d\d \d\d:\d\d):(.+ )(\w\w\w)', timestamp)
  date_time = mobj.group(1) # month, day, year, HH:MM
  usec = mobj.group(2)
  tz = mobj.group(3)

  return (usec, date_time + ' ' + tz)

#
# time_to_epoch( timestring )
#
def time_to_epoch( timestamp ):
  pattern = "%b %d, %Y %H:%M %Z" # %f == microseconds, sometimes undocumented
  usecs, timestamp =  extract_usecs( timestamp )
  
  epoch = int(time.mktime(time.strptime(timestamp, pattern)))

  return decimal.Decimal(epoch) + decimal.Decimal(usecs)



#
# epoch_to_8601( epoch )
#
# convert an epoch float containing microseconds to a STIX ISO 8601 format 
# timestring
#
def epoch_to_8601( epoch ):
  ts = datetime.utcfromtimestamp(epoch).replace(microsecond=(epoch - int(epoch)) * 1000000)
  return ts.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

#
# fix_timestamp( timestamp )
#
def fix_timestamp( timestamp ):
  debug_out("TIMESTAMP: %s" % timestamp)
  epoch = time_to_epoch( timestamp )
  debug_out("EPOCH: %d" % epoch)
  return epoch_to_8601( epoch )

#
# crack_csv( row )
#
def crack_csv( row ):
  row = str(row, 'utf-8')
  for packet in csv.reader( [row] ):
    return packet

#
# encode_and_submit_packet( packet )
#
def encode_and_submit_packet( packet ):
  debug_out(packet)
  tcp_ext = None

  # fixup timestamps
  stix_time = fix_timestamp( packet[FRAME_TIME] )

  if packet[IP_PROTO] == '':
    debug_out("empty IP_PROTO")    
    return

  PAYLOAD = ""
  if int(packet[IP_PROTO]) == IANA_TCP:
    PAYLOAD = packet[TCP_PAYLOAD]
    dst_port = packet[TCP_DST_PORT]
    src_port = packet[TCP_SRC_PORT]
    tcp_flags = packet[TCP_FLAGS][2:] # lop off '0x'
    frame_proto = [ "tcp" ]
    tcp_ext = { 'extensions': { 'tcp-ext': { 'src_flags_hex': tcp_flags }}}

  elif int(packet[IP_PROTO]) == IANA_UDP:
    PAYLOAD = packet[UDP_PAYLOAD]
    dst_port = packet[UDP_DST_PORT]
    src_port = packet[UDP_SRC_PORT]
    frame_proto = [ "udp" ]

  raw = binascii.a2b_hex(PAYLOAD.replace(':', ''))

  if B64_PAYLOAD:
    cooked = base64.b64encode(raw)
    cooked = cooked.decode('UTF-8')
  else:
    cooked =  "'{}'".format(''.join(['\\x{:02x}'.format(c) for c in raw]))

  debug_out(cooked)

  stix_observable = {
    'created': stix_time,
    'first_observed': stix_time,
    'id': 'observed-data--' + str(uuid.uuid4()),
    'last_observed': stix_time,
    'modified': stix_time,
    'number_observed': 1,
    'objects': {
      '0': {
        'type': 'ipv4-addr', 
        'value': packet[IP_SRC]
        },
      '1': {
        'type': 'ipv4-addr', 
        'value': packet[IP_DST]},
      '2': {
        'mime_type': 'text/plain',
        'payload_bin': cooked,
        'type': 'artifact'
        },
      '3': {
        'dst_port': dst_port,
        'dst_ref': '1',
        'src_port': src_port,
        'src_ref': '0',
        'protocols': frame_proto,
        'type':'network-traffic',
      },
    'type': 'observed-data'
    }
  }

  # add TLP property to observable if required
  if (TLP != None):
    # add the tlp marking definition
    stix_observable['object_marking_refs'] = [TLP]

  if tcp_ext:
    # add tcp flags to the network-traffic object
    stix_observable['objects']['3'].update(tcp_ext)

  debug_out(stix_observable)

  if STDOUT:
    pprint.pprint(stix_observable)
  else:
    res = requests.post(URL, data=json.dumps(stix_observable), 
                        verify=False, 
                        headers={'content-type': 'application/json'})
    debug_out(res)

  return stix_observable

#
# debug_out( str )
#
def debug_out( str ):
  if (DEBUG == True):
    sys.stderr.write("DEBUG: %s\n" % str)
  else:
    pass

#
# process_pcap( FILE )
#
def process_pcap( FILE ):
  global COUNT
  cmd = (TSHARK_PCAP + TSHARK_FIELDS) % FILE
  debug_out(cmd)

  devnull = open(os.devnull, 'w')
  proc = sp.Popen(shlex.split(cmd), stdout=sp.PIPE, stderr=devnull)

  while (True):
    raw = proc.stdout.readline()
    packet = crack_csv(raw)

    if raw != '' and packet:
      COUNT += 1
      if packet[IP_PROTO] == '':
        packet[IP_PROTO]= 0
      if ((int(packet[IP_PROTO]) != IANA_TCP) and (int(packet[IP_PROTO]) != IANA_UDP)):
        debug_out("Skipping non-TCP/UDP packet.")
        continue
      encode_and_submit_packet(packet)
    else:
      debug_out("Processed %d packets." % COUNT)
      break
  

#
# process_live( IFACE )
#
def process_live( IFACE ):
  global COUNT
  cmd = (TSHARK_LIVE + TSHARK_FIELDS) % IFACE
  debug_out(cmd)
  devnull = open(os.devnull, 'w')
  proc = sp.Popen(shlex.split(cmd), stdout=sp.PIPE, stderr=devnull)

  while (True):
    raw = proc.stdout.readline()
    packet = crack_csv(raw)
    if raw != '' and packet:
      COUNT += 1
      if packet[IP_PROTO] == '':
        packet[IP_PROTO] = 0
      if ((int(packet[IP_PROTO]) != IANA_TCP) and (int(packet[IP_PROTO]) != IANA_UDP)):
        debug_out("skipping")
        continue
      encode_and_submit_packet( packet )
    else:
      if proc.poll():
        sys.exit(proc.poll())
      continue

#
# sig_handler( signal_recieved, frame )
#
def sig_handler(signal_recieved, frame):
  debug_out("Processed %d packets." % COUNT)
  sys.exit(0)


#
# MAIN
#

DEBUG = False

if __name__ == '__main__':
  try:
    opts, args = getopt.getopt(sys.argv[1:], "i:f:dh:sbut:", ["interface=", "file=", "debug", "hostname=", "stdout", "base64", "http", "tlp=" ])
  except getopt.GetoptError as err:
    print(str(err))
    usage()
    sys.exit(2)

  signal.signal(signal.SIGINT, sig_handler)

  IFACE = None
  FILE = None
  DAEMON = False
  HOSTNAME = 'localhost:9200'
  SCHEME = 'http'
  STDOUT = False
  B64_PAYLOAD = False
  TLP = None

  for o, a in opts:
    if o in ("-i", "--interface"):
      IFACE = a
    elif o in ("-d", "--debug"):
      DEBUG = True
    elif o in ("-f", "--file"):
      FILE = a
    elif o in ('-h', '--hostname'):
      HOSTNAME = a
    elif o in ('-s', '--stdout'):
      STDOUT = True
    elif o in ('-b', '--base64'):
      B64_PAYLOAD = True
    elif o in ('-u' '--http'):
      SCHEME = 'http'
    elif o in ('-t', '--tlp'):
      tlp_level = a
      if tlp_level in [ "white", "green", "amber", "red" ]:
        TLP = TLP_MARKINGS[tlp_level]
      else:
        sys.exit("Invalid TLP level.\n")
    else:
      assert False, "Unknown option."

  if (IFACE == None) and (FILE == None):
    usage()
    sys.exit(2)

  if (IFACE != None) and (FILE != None):
    usage()
    sys.exit(2)

  # UID 0 check
  if ( IFACE != None ) and ( os.geteuid() != 0 ):
    sys.exit("Live capture requires 'root' privileges.")

  #URL = urllib.parse.urlunsplit((SCHEME, HOSTNAME, 'index/', '', '') 
  URL = urllib.parse.urlunsplit((SCHEME, HOSTNAME, 'index/stix/', '', ''))

  debug_out(URL)

  if (FILE):
    # process pcap file and exit
    debug_out("Reading PCAP file %s..." % FILE)
    process_pcap(FILE)
  elif (IFACE):
    debug_out("Listening on %s..." % IFACE)
    process_live(IFACE)
