#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import scapy.all as s
import numpy as np

from tqdm import tqdm

nb_request_per_grid = 20

nb_incoming_packets = np.zeros((100, nb_request_per_grid))
nb_outgoing_packets = np.zeros((100, nb_request_per_grid))
sizes_poi_pkts = np.zeros((100, nb_request_per_grid, 18)) # There is at most 18 http requests for a grid query 
"""
Could also be done by extracting the frame numbers of the
http requests containing that "separation" since we can filter
pcap by http, the firsts requests of each query will be located
every X http requests (where X is the number of http requests 
for a query of a given grid). Thus we don't need that, but we
did not have enough time to obtain these.
"""
separation = b'"poi_list"'

for k in tqdm(range(100)):
    
    # Load packets for grid k. Capture with "scripts/capture_server.sh" and "scripts/capture_client.sh"
    path = 'captures/client/client-grid_' + str(k+1) + '.pcap'
    packets = s.rdpcap(path)
    
    # Iterate over the packets
    req_found = 0 # nb_request_per_grid requests per file
    for i, packet in enumerate(packets):

        if(s.Raw in packet):
            act = packet[s.Raw].load
            if(separation in act):

                # Count the number of incoming/outcoming packets from the proxy (between each requests)
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

    # Fill sizes_poi_pkts with files that already have extracted sizes and frame number using "scripts/extract_pkt_sizes.sh"
    path_sizes = 'captures/client_extracted_sizes/poi_pkt_sizes_grid_' + str(k+1) + '.txt'

    frame_nmb_and_sizes_str = []
    with open(path_sizes, 'r') as f:
        frame_nmb_and_sizes_str += f.read().split(',')

    fn_sizes = [(int(fn), int(pkt_size) if len(pkt_size) > 0 else np.nan) for fn, pkt_size in [e.split(';') for e in frame_nmb_and_sizes_str]]

    # find the number of POI for that grid
    if(len(fn_sizes) % nb_request_per_grid == 0):
        nb_poi = int(len(fn_sizes) / nb_request_per_grid)
    else:
        print("ERR: Please check the capture. At least one of the capture files contains errors.")
        exit(1)

    splits = []
    idx = 0

    for i in range(nb_request_per_grid):
        splits.append(fn_sizes[idx:idx+nb_poi])
        idx += nb_poi

    # Prepare the arrays with these values to give it to ML
    for i in range(len(splits)):
        sizes_poi_pkts[k, i, :] = np.pad([pkt_size for _, pkt_size in splits[i]], (0, sizes_poi_pkts.shape[2]-len(splits[i])), constant_values=0)

    for i in range(sizes_poi_pkts.shape[1]):
        if all(v == 0 for v in sizes_poi_pkts[k,i,:]):
            sizes_poi_pkts[k,i,:] = np.nan

    # fill zeros with the mean of the column
    col_mean = np.nanmean(sizes_poi_pkts[k,:,:], axis=0)
    col_mean = np.array([float(round(v)) for v in col_mean])
    idxs = np.where(np.isnan(sizes_poi_pkts[k,:,:]))
    sizes_poi_pkts[k][idxs] = np.take(col_mean, idxs[1])

# At 3 indices, nb_outgoing_packets and nb_incoming_packets are 0 because of errors coming from the server
# Compute other useful features
nb_out_fraction = nb_outgoing_packets/(nb_outgoing_packets+nb_incoming_packets)
nb_in_fraction = nb_incoming_packets/(nb_outgoing_packets+nb_incoming_packets)
nb_packets = nb_outgoing_packets + nb_incoming_packets

# Change nan to mean of the row
row_mean = np.nanmean(nb_out_fraction, axis=1)
row_mean = np.array([float(round(v)) for v in row_mean])
idxs = np.where(np.isnan(nb_out_fraction))
nb_out_fraction[idxs] = np.take(row_mean, idxs[0])

row_mean = np.nanmean(nb_in_fraction, axis=1)
row_mean = np.array([float(round(v)) for v in row_mean])
idxs = np.where(np.isnan(nb_in_fraction))
nb_in_fraction[idxs] = np.take(row_mean, idxs[0])

# Save in numpy format
np.save('nb_out_packets.npy', np.asarray(nb_outgoing_packets))
np.save('nb_in_packets.npy', np.asarray(nb_incoming_packets))
np.save('nb_out_packets_frac.npy', np.asarray(nb_out_fraction))
np.save('nb_in_packets_frac.npy', np.asarray(nb_in_fraction))
np.save('nb_packets.npy', np.asarray(nb_packets))
np.save('sizes_poi_pkts.npy', np.asarray(sizes_poi_pkts))