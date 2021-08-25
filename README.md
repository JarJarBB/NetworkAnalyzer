# NetworkAnalyzer
SNIX -- An elegant, easy-to-use packet analyzer.

Compile with the "make" command on a Linux operating system.
If you launch the "snix" program without any options, it will analyze the default interface.

The CLI options are as follows:

-i <interface>: interface for live analysis
-o <file> : PCAP file
-f <filter> : BPF filter
-v <1..3> : verbosity level

"Snix" implements these protocols:

- Ethernet
- IPv4
- IPv6
- UDP
- TCP
- ARP
- BOOTP and DHCP
- DNS
- HTTP
- FTP
- SMTP
- POP
- IMAP
- TELNET

Each of these protocols has been tested with several PCAP packets.

The structure of the program is simple:

Each X() function of each protocol calls a display_X() function,
and then recursively calls the higher-level protocol Y().
