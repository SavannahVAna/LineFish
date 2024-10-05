import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

public class Main {
    public static void main(String[] args) {
        PcapReader reader = new PcapReader();

        try {
            reader.openPcap("\\C:\\Users\\savpo\\Downloads\\tcp-ecn-sample.pcap\\");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        try {
            reader.readHeader();
            reader.readPacket();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
