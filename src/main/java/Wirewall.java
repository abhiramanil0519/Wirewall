import com.wirewall.network.WirewallEngine;
import com.wirewall.ui.ConsoleColors;
import org.pcap4j.core.*;
import java.util.List;
import java.util.Scanner;

public class Wirewall {
    public static void main(String[] args) throws Exception {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        Scanner input = new Scanner(System.in);

        System.out.println(ConsoleColors.YELLOW_TEXT + "--- Wirewall Network Monitor ---");
        for (int i = 0; i < interfaces.size(); i++) {
            System.out.println("[" + i + "] " + interfaces.get(i).getDescription());
        }

        System.out.print("\nSelect Interface ID: " + ConsoleColors.RESET);
        PcapNetworkInterface device = interfaces.get(input.nextInt());

        String localIp = "";
        for (PcapAddress addr : device.getAddresses()) {
            if (addr.getAddress() instanceof java.net.Inet4Address) {
                localIp = addr.getAddress().getHostAddress();
            }
        }

        WirewallEngine engine = new WirewallEngine(localIp);
        
        PcapHandle handle = device.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 1);
        handle.setFilter("tcp", BpfProgram.BpfCompileMode.OPTIMIZE);

        System.out.println(ConsoleColors.HEADER + String.format("%-6s %-10s %-25s %-25s %-10s %-6s %-40s", 
            " NO", "TIME", "SOURCE", "DESTINATION", "PROT", "LEN", "INFO") + ConsoleColors.RESET);

        handle.loop(-1, engine.getListener());
    }
}