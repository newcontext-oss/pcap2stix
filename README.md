# pcap2stix

This is a testing tool for generating STIXv2 observables from PCAP data. 

## Dependencies

An installation of Wireshark version 3.4.0 or greater with 'tshark' in the path is required.

## Files

### pcap2stix.py
Test tool for converting PCAP data to STIXv2 observables. Currently supports processing both live captures and files. This tool identifies all TCP and UDP packets, extracts source and destination addresses and ports along with the binary payload and creates a STIXv2 observable. This observable can then be submitted to Elasticsearch or output to STDOUT.

```
Usage: pcap2stix.py -i <iface> [-cd]
Options:
 -i <iface>, --interface=<iface>      - interface to listen on
 -f <filename>, --file=<filename>     - file to process
 -h <hostname>, --hostname=<hostname> - host and port of ELK stack (default)
 -s, --stdout                         - output STIX observables to stdout
 -b, --base64                         - output 'payload_bin' in base64
 -d, --debug                          - limited debugging output
 -u                                   - use http instead of https (default)
 -t <tlp_level>, --tlp=<tlp_level>    - enable and define TLP level for observables
```

By default, `payload_bin` is encoded as hexadecimal byte value strings in order to be indexed by elasticsearch. If standard STIXv2 base-64 encoding is required, the `--base64` option can be used.

Valid Traffic Light Protocol (TLP) levels are `white`, `green`, `amber`, and `red`.

### mapping.txt
Miscellaneous commands to properly set up the Elasticsearch database. This forces nanosecond precision on the `created`, `first_seen`, and `last_seen` timestamps when they are imported in to Elasticsearch. 

Copyright &copy; 2019, 2020 - New Context Services, Inc.
