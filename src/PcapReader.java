import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
//Class pcapreader to open, read pcap files and tranform the packets into Protocol objects
public class PcapReader {
    private InputStream input;
    private boolean lilendian = false;
    private String stamp;
    private final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
    //to open pcap
    public ArrayList<Packet> openPcap(String filename) throws FileNotFoundException {
        ArrayList<Packet> packets = new ArrayList<>();
        try{
            this.input = new BufferedInputStream(new FileInputStream(filename));
            readHeader();
            int bytesread;
            byte[] buffer = new byte[16];
            while ((bytesread = input.read(buffer)) != -1){
               packets.add(readPacket(buffer));
            }
            input.close();
        } catch (FileNotFoundException e) {
            System.out.println("File not found: " + filename);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return packets;
    }

    //takes informations from header
    public void readHeader() throws IOException{
        byte[] header = new byte[24];
        input.read(header);

        //gets the magic number to see if the file is written in big or little andian and act accordingly
        int magicNumber = ((header[0] & 0xFF) << 24) | ((header[1] & 0xFF) << 16) | ((header[2] & 0xFF) << 8) | (header[3] & 0xFF);
        byte[] hexChars = new byte[header.length * 2];
        if (magicNumber == 0xD4C3B2A1) { //if the order of bytes is inverse then we are in little andian
            for (int i = 0; i < header.length / 2; i++) {
                byte temp = header[i];
                header[i] = header[header.length - i - 1];
                header[header.length - i - 1] = temp;
            }
            lilendian = true;
        }
        for (int j = 0; j < header.length; j++) {
            int v = header[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }

        //TODO simplify

        String headerString = new String(hexChars, StandardCharsets.UTF_8);
        String micro = "0000000100002000000000000000000000040002A1B2C3D4";
        String nano = "0000000100002000000000000000000000040002A1B2C34D";
        //checks if the timestamp is in seconds and micro/nano seconds
        if (micro.equals(headerString)) {
            stamp = "micro";
        }
        else if (nano.equals(headerString)) {
            stamp = "nano";
        }
    }


    public Packet readPacket(byte[] header) throws IOException{
        //read the header of the packet

        ByteBuffer timeS = ByteBuffer.wrap(header, 0, 4);
        ByteBuffer timesms = ByteBuffer.wrap(header, 4, 4);
        ByteBuffer datanb = ByteBuffer.wrap(header, 8, 4);
        int timestampS;
        int timestampMS;
        int packetlength;

        if(lilendian){
            timeS.order(ByteOrder.LITTLE_ENDIAN);
            timesms.order(ByteOrder.LITTLE_ENDIAN);
            datanb.order(ByteOrder.LITTLE_ENDIAN);
        }

        timestampS = timeS.getInt();
        timestampMS = timesms.getInt();
        packetlength = datanb.getInt();

        byte[] data = new byte[packetlength];
        input.read(data);
        //create a packet object with the data
        return new Packet(data,timestampS,timestampMS, lilendian);

    }
}
