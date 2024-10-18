import java.io.FileNotFoundException;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class Main2 {
    public static void main(String[] args) throws FileNotFoundException, UnknownHostException {
        PcapReader reader = new PcapReader();
        ArrayList<Packet> packetList = reader.openPcap("C:\\Users\\savpo\\Downloads\\tcp-ecn-sample.pcap");
        Options.TCPStream(packetList,3);
    }
}
