import socket # https://docs.python.org/3/library/socket.html
import struct # https://docs.python.org/3/library/struct.html#format-characters


# unpack the ethernet frame. For more info on the format, see here: https://www.geeksforgeeks.org/ethernet-frame-format/
def ethernet_frame(data):
    # ! means data is being treated as network data (i.e. Big endian) since this was coded on a computer with
    # x64 architecture which is little endian
    receiver_MAC, sender_MAC, data_length = struct.unpack("! 6s 6s H", data[:14]) # destination and source addresses are 6 bytes in data frame, length occupies 2 bytes

    # unpacked values are currently stored as bytes. Pass them into format_mac to format them into a human-readable format 
    return (receiver_MAC, sender_MAC, socket.htons(data_length), # convert length back to device's appropriate endianness
            data[14:])

def format_mac(byte_addr):
    addr = "{:02x}".format(byte_addr[0:2])
    for i in range(len(byte_addr) + 2, len(byte_addr), 2): # MAC addressess are split in chunks of two bytes, for 12 (48 bits) bytes. See here for more: https://www.geeksforgeeks.org/introduction-of-mac-address-in-computer-network/
        addr += ":{:02X}".format(byte_addr[i: i+2])
    return addr

# "{:02X}".format("123456".encode())

if __name__ == "__main__":
    # specify AF_PACKET family to ensure no transport protocol. That way, raw ethernet packet can be obtained instead of having extra UDP/TCP/etc. headers
    # specify SOCK_RAW to gain direct access to the lower layer protocols, primarily IP, so we can sniff the packets 
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = sock.recvfrom(65536)
        dest_mac, src_mac, length, data = ethernet_frame(raw_data)

        print("\nEthernet Frame:")
        print("Destination: {}, Source: {}, Protocol: {}".format(dest_mac,src_mac, length))