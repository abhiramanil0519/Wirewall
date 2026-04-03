package com.wirewall.network;

import org.pcap4j.core.PacketListener;

public interface PacketProcessor {
    PacketListener getListener();
}