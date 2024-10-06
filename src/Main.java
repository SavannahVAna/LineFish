import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;

public class Main {
    public static void main(String[] args) {
        PcapReader reader = new PcapReader();

        try {
            ArrayList<Packet> packetList = reader.openPcap("\\C:\\Users\\savpo\\Downloads\\tcp-ecn-sample.pcap\\");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }

    }

}
