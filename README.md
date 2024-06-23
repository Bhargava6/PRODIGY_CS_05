Network Packet Analyzer

This packet sniffer tool is designed to capture and analyze network packets, displaying information such as source and destination IP addresses, protocols, and payload data. The program leverages the scapy library, which is a powerful Python library used for network packet manipulation and analysis.

The script starts by importing necessary functions and classes from the scapy library, including sniff, IP, TCP, UDP, and Raw. These imports allow the program to capture and dissect various network packets.

The core of the program is the analyze_packet function. This function processes each packet captured by the sniffer. It first checks if the packet has an IPv4 layer (IP). If the packet does not contain an IPv4 layer, the function returns early, thereby avoiding unnecessary processing for irrelevant packets.

For packets with an IPv4 layer, the function extracts the source IP address (src_ip), destination IP address (dst_ip), and the protocol number. It then maps the protocol number to a human-readable name using a dictionary, making the protocol information more understandable.

Next, the function checks if the packet contains either a TCP or UDP layer. If the packet has a TCP or UDP layer, the function extracts the source and destination ports and prints them. It also determines the type of the transport layer (TCP or UDP) and prints this information.

If the packet has a Raw layer, which typically contains the payload data, the function attempts to decode this payload as a UTF-8 string. If the decoding is successful, it prints the payload data; otherwise, it indicates that the payload is unprintable.

After processing each packet, the function prints a separator line for better readability of the output.

The start_sniffing function initiates the packet sniffing process. It accepts an optional network interface parameter. If an interface is provided, it includes this information in the startup message; otherwise, it defaults to the system's default network interface. The sniff function from scapy is called to start capturing packets, with each captured packet being passed to the analyze_packet function for processing.

The main execution block checks for command-line arguments to determine the network interface to use for sniffing. If an interface is specified, it is passed to the start_sniffing function; otherwise, the function is called without any arguments, defaulting to the system's default interface.
