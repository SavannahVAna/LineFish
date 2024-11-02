import java.io.FileNotFoundException;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class Main2 {
    public static void main(String[] args) throws FileNotFoundException, UnknownHostException {
        PcapReader reader = new PcapReader();
        int nb;
        String filename;
        if (args.length == 0) {
            filename= "C:\\Users\\savpo\\Downloads\\pcaps\\pcaps\\tcp.pcap";
            nb = 11;
        }
        else{
            filename= args[0];
            nb = Integer.parseInt(args[1]);
        }

        ArrayList<Packet> packetList = reader.openPcap(filename);
        Options.TCPStream(packetList,nb);
    }
}
