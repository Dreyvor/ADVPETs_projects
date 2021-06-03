#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jun  2 16:10:37 2021

@author: benoit
"""

import scapy.all as s
import numpy as np


nb_incoming_packets = np.zeros((100,20))
nb_outgoing_packets = np.zeros((100,20))
separation = b'"poi_list"'

for k in range(100):
    
    # Load packets for grid k
    path = 'client/client-grid_' + str(k+1) + '.pcap'
    packets = s.rdpcap(path)
    
    print("CELL : ", k, path)
    
    # Iterate over the packets
    req_found = 0 # 20 requests per file
    for i,packet in enumerate(packets):

        if(s.Raw in packet):
            act = packet[s.Raw].load
            if(separation in act):

                # Count the number of incoming packets from the proxy (between each requests)
                nb_inc_pkt = 0
                nb_out_pkt = 0
                next_req = False
                j = 1
                while(not next_req):

                    if(i+j >= len(packets)):
                        nb_incoming_packets[k][req_found] = nb_inc_pkt
                        nb_outgoing_packets[k][req_found] = nb_out_pkt
                        break

                    new_pkt = packets[i+j]
                    if(s.TCP in new_pkt):
                        if(new_pkt[s.TCP].sport == 9050): #if the packet comes from the proxy
                            nb_inc_pkt = nb_inc_pkt + 1
                        if(new_pkt[s.TCP].dport == 9050): #if the packet goes to the proxy
                            nb_out_pkt = nb_out_pkt + 1

                    if(s.Raw in new_pkt): # check if it is the next request
                        if(separation in new_pkt.load):
                            next_req = True
                            nb_incoming_packets[k][req_found] = nb_inc_pkt
                            nb_outgoing_packets[k][req_found] = nb_out_pkt
                            req_found = req_found + 1

                    j = j + 1

                i = j

'''
# Remove rows containing a '0'
idx_to_remove_1 = np.asarray(np.where(np.any(nb_outgoing_packets == 0, axis=1))).flatten()
idx_to_remove_2 = np.asarray(np.where(np.any(nb_incoming_packets == 0, axis=1))).flatten()
idx_to_remove = np.unique(np.concatenate((idx_to_remove_1, idx_to_remove_2)))

nb_outgoing_packets = np.array([arr for i,arr in enumerate(nb_outgoing_packets) if i not in idx_to_remove])
nb_incoming_packets = np.array([arr for i,arr in enumerate(nb_incoming_packets) if i not in idx_to_remove])
'''

# At 3 indices, nb_outgoing_packets and nb_incoming_packets are 0 because of errors coming from the server
# Compute other useful features
nb_out_fraction = nb_outgoing_packets/(nb_outgoing_packets+nb_incoming_packets)
nb_in_fraction = nb_incoming_packets/(nb_outgoing_packets+nb_incoming_packets)
nb_packets = nb_outgoing_packets + nb_incoming_packets

# Change nan to 0
nb_out_fraction = np.where(np.isnan(nb_out_fraction), 0, nb_out_fraction)
nb_in_fraction = np.where(np.isnan(nb_in_fraction), 0, nb_in_fraction)

# Save in numpy format
np.save('nb_out_packets.npy', np.asarray(nb_outgoing_packets))
np.save('nb_in_packets.npy', np.asarray(nb_incoming_packets))
np.save('nb_out_packets_frac.npy', np.asarray(nb_out_fraction))
np.save('nb_in_packets_frac.npy', np.asarray(nb_in_fraction))
np.save('nb_packets.npy', np.asarray(nb_packets))
