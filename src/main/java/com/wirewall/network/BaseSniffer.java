package com.wirewall.network;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public abstract class BaseSniffer {
    protected static final ConcurrentHashMap<String, String> dnsCache = new ConcurrentHashMap<>();
    private final ExecutorService dnsExecutor = Executors.newFixedThreadPool(5);

    protected String getFastIdentifier(InetAddress addr) {
        String ip = addr.getHostAddress();
        if (dnsCache.containsKey(ip)) return dnsCache.get(ip);

        dnsExecutor.submit(() -> {
            try {
                String hostname = addr.getCanonicalHostName();
                if (!hostname.equalsIgnoreCase(ip)) dnsCache.put(ip, hostname);
            } catch (Exception ignored) {}
        });
        return ip;
    }

    protected String truncate(String str, int len) {
        if (str == null) return "";
        return (str.length() <= len) ? str : str.substring(0, len - 3) + "...";
    }
}