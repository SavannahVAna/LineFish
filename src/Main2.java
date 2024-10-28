import java.io.FileNotFoundException;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class Main2 {
    public static void main(String[] args) throws FileNotFoundException, UnknownHostException {
        PcapReader reader = new PcapReader();
        //String filename= args[0];
        //int nb = Integer.parseInt(args[1]);
        String filename= "C:\\Users\\savpo\\Downloads\\pcaps\\pcaps\\tcp.pcap";
        int nb = 11;
        ArrayList<Packet> packetList = reader.openPcap(filename);
        Options.TCPStream(packetList,nb);
    }
}
