import packet_struct
import sys
import struct
import socket

class Connection:
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        # Connection address information
        self.address = (src_ip, src_port, dst_ip, dst_port)
        # List to store packets associated with this connection
        self.packets = []
        # Dictionary to store count of different flags
        self.flags = {'ACK': 0, 'RST': 0, 'SYN': 0, 'FIN': 0}
        # Initial state of the connection
        self.state = "S0F0"
        # Dictionary to store packets sent from src and dst
        self.packets_sent = {src_ip: 0, dst_ip: 0}
        # Dictionary to store bytes sent from src and dst
        self.bytes_sent = {src_ip: 0, dst_ip: 0}
        # Timing information for the connection
        self.start_time = float("inf")
        self.end_time = float("-inf")
        # Window size metrics
        self.total_window = 0
        self.min_window = float("inf")
        self.max_window = float("-inf")
        # Round Trip Time (RTT) values
        self.rtt_values = []
        # Unique identifier for the connection
        self.ID = pack_id(self.address)

    # Processes a packet: stores and analyzes its information.
    def process_packet(self, packet_data):
        self.store_packet(packet_data)
        self.update_flags(packet_data)
        self.record_traffic_stats(packet_data)
        self.update_timing(packet_data)
        self.update_window_metrics(packet_data)

    # Stores packet information in the connection.
    def store_packet(self, packet_data):
        self.packets.append(packet_data)

    # Updates the flag counts based on the current packet.
    def update_flags(self, packet_data):
        for flag in ["ACK", "RST", "SYN", "FIN"]:
            self.flags[flag] = self.flags.get(flag, 0) + packet_data.TCP_header.flags.get(flag, 0)

    # Records the number of packets and bytes sent by the source and destination.
    def record_traffic_stats(self, packet_data):
        src_ip = packet_data.IP_header.src_ip
        self.packets_sent[src_ip] = self.packets_sent.get(src_ip, 0) + 1
        self.bytes_sent[src_ip] = self.bytes_sent.get(src_ip, 0) + packet_data.get_payload()

    # Updates the start and end times of the connection.
    def update_timing(self, packet_data):
        if packet_data.TCP_header.flags["SYN"] and not packet_data.TCP_header.flags["ACK"]:
            self.start_time = min(packet_data.timestamp, self.start_time)
        if packet_data.TCP_header.flags["FIN"] and packet_data.TCP_header.flags["ACK"]:
            self.end_time = max(packet_data.timestamp, self.end_time)

    # Updates the window size statistics for the connection
    def update_window_metrics(self, packet_data):
        window_size = packet_data.TCP_header.window_size
        self.total_window += window_size
        self.min_window = min(window_size, self.min_window)
        self.max_window = max(window_size, self.max_window)


    # Checks if FIN flag was set at any point in the connection
    def is_connection_finished(self):
        return self.flags["FIN"] > 0

    # checks and formats the state of the connection
    def check_connection_state(self):
        ack = self.flags["ACK"]
        rst = self.flags["RST"]
        syn = self.flags["SYN"]
        fin = self.flags["FIN"]

        self.state = "S" + str(syn) + "F" + str(fin)

        if rst > 0:
            self.state += "/R"
        return self.state

    # Calculates RTT between SRC and DST
    # Matches packets from SRC with its ACK packet from DST
    # Returns a list of all rtt times for this connection
    def calculate_rtt(self):
        for src in self.packets:
            # Check if packet is from SRC
            if src.IP_header.src_ip != self.address[0]:
                continue
            ip_len = src.IP_header.ip_header_len
            tcp_offset = src.TCP_header.data_offset
            payload = src.incl_len - ip_len - tcp_offset - 14
            src_seq = src.TCP_header.seq_num
            src_flags = src.TCP_header.flags
            for dst in self.packets:
                # Check if packet is from DST
                if dst.IP_header.src_ip != self.address[2]:
                    continue
                ack = dst.TCP_header.ack_num
                if payload > 0:
                    if ack == src_seq + payload:
                        rtt = get_RTT_value(src, dst)
                        self.rtt_values.append(rtt)
                        break
                elif payload == 0:
                    if src_seq + 1 == ack:
                        if src_flags["SYN"] == 1 or src_flags["FIN"] == 1:
                            rtt = get_RTT_value(src, dst)
                            self.rtt_values.append(rtt)
                            break
        return self.rtt_values

    # returns if this is a complete connection
    def is_complete(self):
        return self.flags["SYN"] > 0 and self.flags["FIN"] > 0

    # returns if connection was reset
    def is_reset(self):
        return self.flags["RST"] > 0

    # returns if connection was still open when trace ended
    def is_open(self):
        return self.flags["SYN"] > 0 and self.flags["FIN"] == 0

    # Calculates the total connection time
    # returns a 3-tuple, start time, end time, and total time
    def get_connection_time(self):
        if self.end_time == float('-inf'):
            self.end_time = self.packets[len(self.packets) - 1].timestamp
        return self.start_time, self.end_time, self.end_time - self.start_time

    # returns number of packets sent by src
    def get_src_packet_total(self):
        return self.packets_sent[self.address[0]]

    # return number of packets sent by dst
    def get_dst_packet_total(self):
        return self.packets_sent[self.address[2]]

    # returns total bytes sent by src
    def get_src_bytes_total(self):
        return self.bytes_sent[self.address[0]]

    # returns total bytes sent by dst
    def get_dst_bytes_total(self):
        return self.bytes_sent[self.address[2]]

    # returns total number of bytes sent in connection
    def get_num_bytes(self):
        return self.bytes_sent[self.address[0]] + self.bytes_sent[self.address[2]]

    # returns number of rtt pairs in connection
    def get_num_rtt_pairs(self):
        return len(self.rtt_values)

    # returns total number of packets sent
    def get_num_packets(self):
        return len(self.packets)

# Helper function to generate a unique identifier for the connection
def pack_id(buffer):
    src_ip, src_port, dst_ip, dst_port = buffer
    key = struct.unpack("!I", socket.inet_aton(src_ip))[0] + struct.unpack("!I", socket.inet_aton(dst_ip))[0] + src_port + dst_port
    return key

# Helper function to calculate RTT
def get_RTT_value(p, other):
    rtt = other.timestamp - p.timestamp
    return round(rtt, 8)

# Function to check and process packets to determine if they belong to a known connection
def check_connection(packet, connections):
    src_ip = packet.IP_header.src_ip
    dst_ip = packet.IP_header.dst_ip
    src_port = packet.TCP_header.src_port
    dst_port = packet.TCP_header.dst_port
    buffer = (src_ip, src_port, dst_ip, dst_port)
    ID = pack_id(buffer)

    if ID not in connections:
        c = Connection(src_ip, src_port, dst_ip, dst_port)
        c.process_packet(packet)
        connections[ID] = c
    else:
        connections[ID].process_packet(packet)

def load_general_header(data):
    gen_header = packet_struct.General_Header()
    gen_header.set_magic_number(data[0:4])
    gen_header.set_version_major(data[4:6])
    gen_header.set_version_minor(data[6:8])
    gen_header.set_zone(data[8:12])
    gen_header.set_sigfigs(data[12:16])
    gen_header.set_snaplen(data[16:20])
    gen_header.set_network(data[20:24])
    return gen_header

def load_packet_header(packet_num, data, time, micro):
    packet = packet_struct.packet()
    buff1 = data[0:4]
    buff2 = data[4:8]
    incl_len = data[8:12]
    orig_len = data[12:16]

    packet.packet_No_set(packet_num)
    packet.timestamp_set(buff1, buff2, time, micro)
    packet.packet_incl_len_set(incl_len)
    packet.packet_size_set(orig_len)
    packet.buffer = data
    return packet

def load_ethernet_header(data):
    header = packet_struct.Ethernet_Header()
    header.set_dest_addr(data[0:6])
    header.set_src_addr(data[6:12])
    header.set_type(data[12:14])
    return header

def load_ip_header(data):
    header = packet_struct.IP_Header()
    src = data[26:30]
    dest = data[30:34]
    total_len = data[16:18]
    header_len = data[14:15]

    header.get_IP(src, dest)
    header.get_total_len(total_len)
    header.get_header_len(header_len)
    return header

def load_tcp_header(data):
    header = packet_struct.TCP_Header()
    src_port = data[34:36]
    dest_port = data[36:38]
    seq_num = data[38:42]
    ack_num = data[42:46]
    data_offset = data[46:47]
    flags = data[47:48]
    w1 = data[48:49]
    w2 = data[49:50]

    header.get_src_port(src_port)
    header.get_dst_port(dest_port)
    header.get_seq_num(seq_num)
    header.get_ack_num(ack_num)
    header.get_data_offset(data_offset)
    header.get_window_size(w1, w2)
    header.get_flags(flags)
    return header

# Print connection details, check if the connection is complete, and print the end separator
def print_connection_stats(inc, conn):
    print(f"Connection {inc}:")
    print("Source Address: ", conn.address[0])
    print("Destination Address: ", conn.address[2])
    print("Source Port: ", conn.address[1])
    print("Destination Port: ", conn.address[3])
    print("Status: ", conn.check_connection_state())
    if conn.is_complete():
        start_time, end_time, total_time = conn.get_connection_time()
        print(f"Start Time: {start_time} seconds")
        print(f"End Time: {end_time} seconds")
        print("Duration: ", str(round(total_time, 6)), "seconds")
        print("Number of packets sent from Source to Destination: ", conn.get_src_packet_total())
        print("Number of packets sent from Destination to Source: ", conn.get_dst_packet_total())
        print("Total number of packets: ", conn.get_num_packets())
        print("Number of packets sent from Source to Destination: ", conn.get_src_bytes_total())
        print("Number of packets sent from Destination to Source: ", conn.get_dst_bytes_total())
        print("Total number of data bytes: ", conn.get_num_bytes())
    print("END")
    if inc == 48:
        print("________________________________________________")
    else:
        print("++++++++++++++++++++++++++++++++")

# Print general statistics about the TCP connections
def print_general_stats(total_connections, complete_connections, reset_connections, open_connections):
    print("\nC) General \n")
    print("Total number of complete TCP connections: ", complete_connections)
    print("Number of reset TCP connections: ", reset_connections)
    print("Number of TCP connections that were still open when the trace capture ended: ", open_connections)
    print("________________________________________________")

# Print detailed statistics for complete TCP connections
def print_detailed_stats(min_time, mean_time, max_time, total_rtt, min_rtt, mean_rtt, max_rtt, complete_connections, min_packets, mean_packets, max_packets, min_window, mean_window, max_window, total_packets):
    print("\nD) Complete TCP connections:\n")
    print("Minimum time duration: %2f" % min_time + " seconds")
    print("Mean time duration: %2f" % (mean_time / complete_connections if complete_connections else 0) + " seconds")
    print("Maximum time duration: %2f" % max_time + " seconds")
    print("")
    print("Minimum RTT value: ", min_rtt)
    print("Mean RTT value: ", round(mean_rtt / total_rtt, 6) if total_rtt else 0)
    print("Maximum RTT value: ", max_rtt)
    print("")
    print("Minimum number of packets including both send/received: ", min_packets)
    print("Mean number of packets including both sent/received: ", mean_packets / complete_connections if complete_connections else 0)
    print("Maximum number of packets including both sent/received: ", max_packets)
    print("")
    print("Minimum receive window size including both sent/received: ", str(min_window) + " bytes")
    print("Mean receive window size including both sent/received: %2f " % (mean_window / total_packets if total_packets else 0), "bytes")
    print("Maximum receive window size including both sent/received: ", str(max_window) + " bytes")
    print("________________________________________________")

def connection_details(connections):
    inc = 1
    complete_connections = 0
    reset_connections = 0
    open_connections = 0
    total_packets = 0
    min_time = float('inf')
    mean_time = 0
    max_time = float('-inf')
    min_packets = float('inf')
    mean_packets = 0
    max_packets = float('-inf')
    min_rtt = float('inf')
    mean_rtt = 0
    max_rtt = float('-inf')
    total_rtt = 0
    min_window = float('inf')
    mean_window = 0
    max_window = float('-inf')

    print("A) Total number of connections: ", len(connections))
    print("________________________________________________")
    print("\nB) Connections' details:")
    for conn in connections.values():
        start_time, end_time, total_time = conn.get_connection_time()
        if conn.is_complete():
            complete_connections += 1
            total_packets += conn.get_num_packets()
            min_time = min(total_time, min_time)
            mean_time += total_time
            max_time = max(total_time, max_time)
            min_packets = min(conn.get_num_packets(), min_packets)
            mean_packets += conn.get_num_packets()
            max_packets = max(conn.get_num_packets(), max_packets)
            rtt = conn.calculate_rtt()
            if rtt:
                min_rtt = min(min(rtt), min_rtt)
                mean_rtt += sum(rtt)
                max_rtt = max(max(rtt), max_rtt)
            total_rtt += conn.get_num_rtt_pairs()
            min_window = min(conn.min_window, min_window)
            mean_window += conn.total_window
            max_window = max(conn.max_window, max_window)
        if conn.is_reset():
            reset_connections += 1
        if conn.is_open():
            open_connections += 1
        print_connection_stats(inc, conn)       
        inc += 1
 
    print_general_stats(len(connections), complete_connections, reset_connections, open_connections)
    print_detailed_stats(min_time, mean_time, max_time, total_rtt, min_rtt, mean_rtt, max_rtt, complete_connections, min_packets, mean_packets, max_packets, min_window, mean_window, max_window, total_packets)

def main():
    # Read CAP file and process packets, then output connection details
    file_name = sys.argv[1]
    file = open(file_name, "rb")

    # Lists for packets and connections
    packets = []
    connections = {}

    # Read and skip global header
    data = file.read(24)
    gen_header = load_general_header(data)

    # Read first packet header
    data = file.read(16)
    orig_time = data[0:4]
    orig_micro = data[4:8]
    packet_num = 0
    packets.append(load_packet_header(packet_num, data, orig_time, orig_micro))

    # Read first packet data
    data = file.read(packets[packet_num].incl_len)
    packets[packet_num].Ethernet_header = load_ethernet_header(data)
    packets[packet_num].IP_header = load_ip_header(data)
    packets[packet_num].TCP_header = load_tcp_header(data)
    check_connection(packets[packet_num], connections)

    while True:
        try:
            data = file.read(16)
            packet_num += 1
            packets.append(load_packet_header(packet_num, data, orig_time, orig_micro))

            data = file.read(packets[packet_num].incl_len)
            packets[packet_num].Ethernet_header = load_ethernet_header(data)
            packets[packet_num].IP_header = load_ip_header(data)
            packets[packet_num].TCP_header = load_tcp_header(data)
            check_connection(packets[packet_num], connections)
        except struct.error:
            break

    # Output
    connection_details(connections)

if __name__ == '__main__':
    main()