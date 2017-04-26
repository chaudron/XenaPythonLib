#!/usr/bin/env python

import sys
import time
import logging

from xenalib.XenaSocket import XenaSocket
from xenalib.XenaManager import XenaManager
from xenalib.StatsCSV import write_csv


logging.basicConfig(level=logging.INFO)


def build_test_packet(stream):
    try:
        import scapy.layers.inet as inet
        import scapy.utils as utils
    except:
        logging.info("Packet: Using sample packet")
        packet_hex = '0x525400c61020525400c6101008004500001400010000400066e70a0000010a000002'
    else:
        logging.info("Packet: Using scapy to build the test packet")
        L2 = inet.Ether(src="52:54:00:C6:10:10", dst="52:54:00:C6:10:20")
        L3 = inet.IP(src="10.0.0.{}".format(stream), dst="10.1.0.{}".format(stream))
        packet = L2/L3/inet.UDP()
        packet_str = str(packet)
        packet_hex = '0x' + packet_str.encode('hex')
        # Uncomment below to see the packet in wireshark tool
        #utils.wireshark(packet)

    logging.debug("Packet string: %s", packet_hex)
    return packet_hex

def run(packet_size):
    # create the test packet
    pkthdr = build_test_packet(1)
    # create the communication socket
    xsocket = XenaSocket('10.19.17.64')
    if not xsocket.connect():
        sys.exit(-1)

    # create the manager session
    xm = XenaManager(xsocket, 'test')

    # add port 0 and configure
    port0 = xm.add_port(1, 0)
    if not port0:
        print "Fail to add port"
        sys.exit(-1)

    port0.set_pause_frames_off()
    # add port 1 and configure
    port1 = xm.add_port(1, 1)
    if not port1:
        print "Fail to add port"
        sys.exit(-1)

    port1.set_pause_frames_off()

    # add a single stream and configure
    stream_no = 30
    for i in range(0, stream_no):
        s1_p0 = port0.add_stream(i)
        s1_p0.set_stream_on()
        s1_p0.disable_packet_limit()
        s1_p0.set_rate_fraction(1000000/stream_no)
#        s1_p0.set_rate_pps(100.0/stream_no)
        s1_p0.set_packet_header(pkthdr)
        s1_p0.set_packet_length_fixed(packet_size, 1518)
        s1_p0.set_packet_payload_incrementing('0x00')
        s1_p0.set_test_payload_id(i + 1)
        s1_p0.set_frame_csum_on()

    # start the traffic
    port0.start_traffic()
    time.sleep(4)

    # fetch stats
    for i in range(1,60):
        port1.grab_all_rx_stats()
        time.sleep(1)

    # stop traffic
    port0.stop_traffic()


    # release resources
    print "Packet size = {}".format(packet_size)
    print "TID  Min latency      Average latency  Max latency"
    print "---  ---------------  ---------------  ---------------"

    full_stats = port1.dump_all_rx_stats()
    avg_tot_lat = max_tot_lat = min_tot_lat = 0


    for i in range(0, stream_no): 
        avg_lat = max_lat = min_lat = cnt = 0
        for timestamp in full_stats.keys():
            stats = full_stats[timestamp]
            lat = stats['pr_tpldlatency']['{}'.format(i +1)]['avg']
            max_tmp = stats['pr_tpldlatency']['{}'.format(i + 1)]['max']
            min_tmp = stats['pr_tpldlatency']['{}'.format(i + 1)]['min']
            max_lat = max_tmp if max_tmp > max_lat else max_lat
            min_lat = min_tmp if min_tmp < min_lat or min_lat == 0 else min_lat
            avg_lat += lat
            cnt += 1
    
        avg_tot_lat += avg_lat
        max_tot_lat = max_lat if max_tot_lat < max_lat else max_tot_lat
        min_tot_lat = min_lat if min_tot_lat > min_lat or min_tot_lat == 0 else min_tot_lat
        print "{:3}  {:15,}  {:15,}  {:15,}".format(i + 1 , min_lat, avg_lat / cnt, max_lat)

    print "Tot. {:15,}  {:15,}  {:15,}\n".format(min_tot_lat, 
                                                 avg_tot_lat / (stream_no * cnt), 
                                                 max_tot_lat)

    write_csv("latency.csv", "Latency RX Stats", full_stats)
    del xm
    del xsocket


def main():
    for pkt in [512, 1024, 1280, 1518]:
        run(pkt)

if __name__ == '__main__':
    main()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
