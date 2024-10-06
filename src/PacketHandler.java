import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PacketHandler {
    //public EtherPacket AnalyseEther(Packet packet) {

    //}

    public static void printPacket(Packet packet) {
        System.out.println(packet.getTimestampS());
        byte[] packetData = packet.getData();
        ByteBuffer buffer = ByteBuffer.wrap(packetData);
        if(packet.isLilendian()){
            buffer.order(ByteOrder.LITTLE_ENDIAN);
        }
        StringBuilder hexString = new StringBuilder();
        while (buffer.hasRemaining()) {
            byte b = buffer.get();
            hexString.append(String.format("%02X ", b)); // Conversion en hexadécimal avec deux chiffres
        }
        System.out.println(hexString);

    }
}
