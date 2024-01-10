# CSC361 Assignment 2 - Connection Analyze

The Connection Analyzer is a Python script that analyzes network packet data captured in a pcap (Packet Capture) file. 
It processes TCP connections and provides statistics and details about each connection, such as the number of packets, 
bytes sent, connection duration, and more. The script uses the `packet_struct` module to parse packet headers and extract 
relevant information.

Features

- Parses pcap files to extract packet data.
- Identifies TCP connections and analyzes their properties.
- Calculates round-trip times (RTT) for each connection.
- Provides detailed statistics for complete connections, including connection duration, packet counts, and window size.
- Reports on the total number of connections, completed connections, reset connections, and open connections in the pcap file.

Usage

To use the Connection Analyzer, follow these steps:

1. Install Python: Make sure you have Python installed on your system. This script is compatible with Python 3.

2. Dependencies: The script relies on the `packet_struct` module for parsing packet headers. Ensure that the `packet_struct` 
   module is available in your project directory or accessible via Python's import system.

3. Capture File: Prepare a pcap (Packet Capture) file that contains network packet data you want to analyze.

4. Run the Script: Execute the script by providing the pcap file as a command-line argument. For example:

   python3 a2.py sample-capture-file.cap
