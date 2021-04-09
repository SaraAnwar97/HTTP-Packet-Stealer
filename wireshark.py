import socket
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
    try:
       return str(raw_ip_addr[0])+"."+str(raw_ip_addr[1])+"."+str(raw_ip_addr[2])+"."+str(raw_ip_addr[3])
    except Exception as e:
        print(e)
        return None

def cal_size(byte,ip_packet_payload: bytes):
    dataOffset = (byte >> 0x04)
    length = len(ip_packet_payload)
    size = length - (dataOffset * 4)
    return dataOffset,size

def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    SrcPort = int.from_bytes(ip_packet_payload[0:2],"big")
    DstPort = int.from_bytes(ip_packet_payload[2:4], "big")
    byte = ip_packet_payload[12]
    dataOffset, size = cal_size(byte, ip_packet_payload)
    payload = ip_packet_payload[-size:]

    return TcpPacket(SrcPort, DstPort, dataOffset, payload)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    byte1 = ip_packet[0]
    ihl = (byte1 & 0x0F)
    source = ip_packet[12:16]
    sourceString = parse_raw_ip_addr(source)
    destinationString = parse_raw_ip_addr(ip_packet[16:20])
    length = ip_packet[2:3]
    length += ip_packet[3:4]
    length = int.from_bytes(length,"big")
    payload = ip_packet[ihl*4:length]
    protocol = ip_packet[9]
    return IpPacket(protocol, ihl, sourceString, destinationString, payload)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, 6)
    while True:
        # Receive packets and do processing here

        packet , addr = stealer.recvfrom(4096)
        IpPacket = parse_network_layer_packet(packet)
        TcpPacket = parse_application_layer_packet(IpPacket.payload)
        try:
            print(TcpPacket.payload.decode("utf-8"))
           # print(TcpPacket.dst_port)
           # print(TcpPacket.src_port)
           # print(IpPacket.destination_address)
           # print(IpPacket.destination_address)
           # print(IpPacket.protocol)
        except:
                pass
    pass


if __name__ == "__main__":
    main()
