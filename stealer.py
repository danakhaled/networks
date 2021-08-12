class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    ip_raw = str(raw_ip_addr[0]) + '.' + str(raw_ip_addr[1]) + '.' + str(raw_ip_addr[2]) + '.' + str(raw_ip_addr[3])
    # print(ip_raw)
    return ip_raw


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    # print("%" * 50)
    # print(ip_packet_payload)
    src_port = (ip_packet_payload[0] << 8) + ip_packet_payload[1]
    # print("TCP Source Port:", src_port)
    dst_port = (ip_packet_payload[2] << 8) + ip_packet_payload[3]
    # print("TCP Destination Port:", dst_port)
    data_offset = (ip_packet_payload[12] >> 4)
    # print("offset", data_offset)
    payload = ip_packet_payload[data_offset * 4:]
    print("TCP payload:", payload)
    try:
        payloaded = payload.decode("UTF-8")
        # print(payloaded)
    except:

        print("CAN NOT BE DECODED")
    # payload = ip_packet_payload
    # print(payload)
    return TcpPacket(src_port, dst_port, data_offset, payload)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    protocol = ip_packet[9]
    # print("Protocol:", protocol)
    ihlbyte = ip_packet[0]
    # print("total", ihlbyte)
    ihl = ihlbyte & 15
    # print("IHL:", ihl)
    source_address = str(ip_packet[12]) + '.' + str(ip_packet[13]) + '.' + str(ip_packet[14]) + '.' + str(ip_packet[15])
    # print("Source Address:", source_address)
    destination_address = str(ip_packet[16]) + '.' + str(ip_packet[17]) + '.' + str(ip_packet[18]) + '.' + str(ip_packet[19])
    # print("Destination Address:", destination_address)
    payload = ip_packet[ihl*4:len(ip_packet)]
    # print(payload)
    return IpPacket(protocol, ihl, source_address, destination_address, payload)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    while True:
        # Receive packets and do processing here
        pass
    pass


if __name__ == "__main__":
    main()
