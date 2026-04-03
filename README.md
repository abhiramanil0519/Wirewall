# Wirewall: Modular TCP Network Monitor

**Wirewall** is a high-performance, real-time network traffic analyzer built in Java. It provides a live-updating dashboard to monitor network packets, specifically focusing on the **TCP Protocol**. 

Built with a professional **Object-Oriented Programming (OOP)** architecture, it features asynchronous DNS resolution and a 24-bit TrueColor terminal interface.

---

## 1. What is this repo about?
Wirewall is a specialized sniffer that captures and analyzes **TCP (Transmission Control Protocol)** traffic. While general sniffers can be overwhelming, Wirewall is optimized to monitor web-handshakes, data streams, and connection resets. 

> **Note:** This version specifically filters and supports **TCP** traffic to ensure high-speed analysis of connection-oriented data.

---

## 2. Installation & Build Guide

### Prerequisites
1. **Java 8 or higher** installed.
2. **Maven** installed (for dependency management).
3. **Npcap** (Windows) or **libpcap** (Linux/Mac) installed. [Download Npcap here](https://npcap.com/).

### Setup & Compilation
Clone the repository and navigate to the project root:

```powershell
# 1. Clean old builds and download dependencies
mvn clean dependency:copy-dependencies

# 2. Compile the OOP package structure
mvn compile

# 3. Run the application
java -cp "target/classes;target/dependency/*" Wirewall
```

---

## 3. Runtime Instructions
As soon as the program launches:

1. **Interface List:** Wirewall scans your hardware and lists all Network Interface Cards (NICs).
2. **User Selection:** You will see a list of adapters (Wi-Fi, Ethernet, etc.) in **Bright Yellow**.
3. **Input:** Type the **ID number** of your active internet adapter and hit `Enter`.
4. **Active Capture:** The program will automatically detect your local IP and start the live dashboard.

---

## 4. Column Explanations
Once the capture starts, the dashboard displays the following data:

| Column | Description |
| :--- | :--- |
| **NO** | The incremental serial number of the captured packet. |
| **TIME** | Seconds elapsed since the capture started. |
| **SOURCE** | The Originator's Domain Name (if resolved) or IP:Port. |
| **DESTINATION** | The Target's Domain Name (if resolved) or IP:Port. |
| **PROT** | The Protocol being captured (Fixed to **TCP**). |
| **LEN** | Total packet size in bytes. |
| **INFO** | TCP details: Flags (`[SYN]`, `[ACK]`, `[PSH]`, `[RST]`) and Seq numbers. |

---

## 5. Row Categorization
Wirewall uses 24-bit ANSI colors to categorize traffic direction and status:

* **🟦 INBOUND (Blue Background):** Traffic arriving at your machine from an external source.
* **⬜ OUTBOUND (White Background):** Traffic being sent from your machine to an external server.
* **🟥 FAILED (Red Background):** Packets with the **TCP RST (Reset)** flag, indicating a refused connection or a blocked port.

---

## 6. Intelligent DNS Resolution
To prevent the dashboard from being a wall of confusing numbers, Wirewall resolves IP addresses into human-readable domain names (e.g., `google.com`).

**How it works:**
The `BaseSniffer` class maintains a `ConcurrentHashMap` as a cache. When a packet arrives, the system checks the cache first. If the IP is new, it returns the IP immediately to prevent lag and triggers a background resolution for the next time that IP appears.

---

## 7. Custom Multi-Threading
Standard DNS lookups are "blocking"—they pause the entire program until the DNS server responds. Wirewall solves this using a **Dedicated Thread Pool**.

**Code Implementation:**
```java
private final ExecutorService dnsExecutor = Executors.newFixedThreadPool(5);

// Offloading resolution to a background thread
dnsExecutor.submit(() -> {
    String hostname = addr.getCanonicalHostName(); 
    dnsCache.put(ip, hostname); // Resolved in the background!
});
```
This ensures the packet sniffer runs at **Wire-Speed**, while name resolution happens quietly in the background without causing a 20-second delay.

---

## 8. OOP Concepts Applied
This project demonstrates the core pillars of Java Object-Oriented Programming:

* **Abstraction:** Defined via the `PacketProcessor` **Interface**. This sets a contract for how any sniffer engine must behave without exposing the complex underlying pcap logic.
* **Inheritance:** `WirewallEngine` **extends** `BaseSniffer`. The engine "inherits" the DNS caching and string formatting logic, following the DRY (Don't Repeat Yourself) principle.
* **Encapsulation:** All sensitive network resources (Thread Pools, Caches) are kept `private` or `protected`. The main `Wirewall.java` only interacts with high-level objects.
* **Modularization:** The project is split into distinct packages:
    * `com.wirewall.network`: Handles the "Backend" packet processing.
    * `com.wirewall.ui`: Handles the "Frontend" ANSI color schemes.

---
```
