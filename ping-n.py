import socket
import struct
import time
import os
import argparse


def checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def create_icmp_packet(ident, seq):
    payload = b'CS/ECE-356: ping payload for nl212!'
    header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    packet_checksum = checksum(header + payload)
    header = struct.pack(
        "!BBHHH",
        8,
        0,
        packet_checksum,
        ident,
        seq
    )
    return header + payload

def ping(host, seq):
    destination_ip = socket.gethostbyname(host)
    ident = os.getpid() & 0xFFFF
    packet = create_icmp_packet(ident, seq)
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_ICMP
    )
    sock.settimeout(1)
    try:
        start_time = time.time()
        deadline = start_time + 1.0
        sock.sendto(packet, (destination_ip, 0))
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise socket.timeout()
            sock.settimeout(remaining)
            response, address = sock.recvfrom(1024)
            ip_header_length = (response[0] & 0x0F) * 4
            icmp_header = response[
                ip_header_length:ip_header_length + 8
            ]
            if len(icmp_header) < 8:
                continue
            reply_type, reply_code, reply_checksum, \
                reply_ident, reply_seq = struct.unpack(
                    "!BBHHH", icmp_header
                )
            if (
                address[0] == destination_ip
                and reply_type == 0
                and reply_code == 0
                and reply_ident == ident
                and reply_seq == seq
            ):
                end_time = time.time()
                rtt = (end_time - start_time) * 1000
                print(
                    f"Reply from {destination_ip}: "
                    f"seq={seq} time={rtt:.2f} ms"
                )
                return rtt
    except socket.timeout:
        print(f"Request timeout for seq={seq}")
        return None
    finally:
        sock.close()

parser = argparse.ArgumentParser()
parser.add_argument(
    "-n",
    type=int,
    required=True,
    help="Number of pings to send"
)
parser.add_argument("host", help="Hostname or IP address to ping")
args = parser.parse_args()
host = args.host
destination_ip = socket.gethostbyname(host)
count = args.n

if count < 1:
    parser.error("-n must be a positive integer")
print(f"Pinging {host} ({destination_ip}) with {count} packets:")
rtts = []

for seq in range(1, count + 1):
    rtt = ping(host, seq)
    if rtt is not None:
        rtts.append(rtt)
    if seq < count:
        time.sleep(1)

sent = count
received = len(rtts)
lost = sent - received
loss_percent = (lost / sent) * 100

print("\n--- Ping Statistics ---")
print(
    f"Packets: Sent = {sent}, Received = {received}, "
    f"Lost = {lost} ({loss_percent:.1f}% loss)"
)

if received > 0:
    average_rtt = sum(rtts) / received
    print(f"Average RTT = {average_rtt:.2f} ms")
else:
    print("Average RTT = N/A (no replies)")


