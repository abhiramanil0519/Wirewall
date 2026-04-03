package com.wirewall.network;

import com.wirewall.ui.ConsoleColors;
import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import java.util.concurrent.atomic.AtomicInteger;

public class WirewallEngine extends BaseSniffer implements PacketProcessor {
    private final String myIp;
    private final long startTime;
    private final AtomicInteger serialNo = new AtomicInteger(1);
    private final AtomicInteger rowCounter = new AtomicInteger(0);
    private final int maxRows = 25;
    private final String format = "%-6s %-10s %-25s %-25s %-10s %-6s %-40s";

    public WirewallEngine(String myIp) {
        this.myIp = myIp;
        this.startTime = System.currentTimeMillis();
    }

    @Override
    public PacketListener getListener() {
        return packet -> {
            TcpPacket tcp = packet.get(TcpPacket.class);
            IpV4Packet ip = packet.get(IpV4Packet.class);

            if (tcp != null && ip != null) {
                refreshUI();

                String src = getFastIdentifier(ip.getHeader().getSrcAddr()) + ":" + tcp.getHeader().getSrcPort().valueAsInt();
                String dst = getFastIdentifier(ip.getHeader().getDstAddr()) + ":" + tcp.getHeader().getDstPort().valueAsInt();
                
                StringBuilder info = new StringBuilder();
                if (tcp.getHeader().getSyn()) info.append("[SYN] ");
                if (tcp.getHeader().getAck()) info.append("[ACK] ");
                if (tcp.getHeader().getPsh()) info.append("[PSH] ");
                if (tcp.getHeader().getRst()) info.append("[RST] ");
                info.append("Seq=").append(tcp.getHeader().getSequenceNumberAsLong());

                String color = ConsoleColors.IN;
                if (tcp.getHeader().getRst()) color = ConsoleColors.FAILED;
                else if (ip.getHeader().getSrcAddr().getHostAddress().equals(myIp)) color = ConsoleColors.OUT;

                System.out.println(color + String.format(format, 
                    serialNo.getAndIncrement(), 
                    String.format("%.4f", (System.currentTimeMillis() - startTime) / 1000.0),
                    truncate(src, 25), truncate(dst, 25), "TCP", packet.length(), truncate(info.toString(), 40)) + ConsoleColors.RESET);
                
                rowCounter.incrementAndGet();
            }
        };
    }

    private void refreshUI() {
        if (rowCounter.get() >= maxRows) {
            for (int i = 0; i < maxRows; i++) {
                System.out.print(ConsoleColors.MOVE_UP + ConsoleColors.CLEAR_LINE);
            }
            rowCounter.set(0);
        }
    }
}