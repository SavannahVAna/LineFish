import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class Main {
    public static void main(String[] args) {
        PcapReader reader = new PcapReader();

        try {
            ArrayList<Packet> packetList = reader.openPcap("\\C:\\Users\\savpo\\Downloads\\tcp-ecn-sample.pcap\\");
            PacketHandler.printPacket(packetList.getFirst());
            EtherPacket newpack = PacketHandler.AnalyseEther(packetList.getFirst());
            System.out.println(newpack.getEtherType());
            PacketHandler.printEtherpacket(newpack);
            IPPacket packet2 = PacketHandler.AnalyseIPv4(newpack);
            System.out.println(packet2.getDestinationIP());
            System.out.println(packet2.getSourceIP());

        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }

    }

}
