import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PacketHandler {
    public static EtherPacket AnalyseEther(Packet packet) {
        byte[] data = packet.getData();
        //prend ce qui va etre la nouvelle partie data dans la frame ethernet
        ByteBuffer buffer = ByteBuffer.wrap(data, 14,data.length-18);
        byte[] remain = new byte[data.length-18];
        System.arraycopy(data, 13, remain, 0, remain.length);
        //puis les futurs attributs de la classe Etherpacket
        ByteBuffer dst = ByteBuffer.wrap(data, 0,6);
        ByteBuffer src = ByteBuffer.wrap(data,6,6);
        ByteBuffer t = ByteBuffer.wrap(data,12,2);
        if(packet.isLilendian()){
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            dst.order(ByteOrder.LITTLE_ENDIAN);
            src.order(ByteOrder.LITTLE_ENDIAN);
            t.order(ByteOrder.LITTLE_ENDIAN);
        }

        short value = t.getShort(); // Lit les deux octets dans un short
        String ethtyp = "inconnu";
        // Comparer avec la valeur hexadécimale 0x0800
        if (value == (short) 0x0800) {
           ethtyp = "IPv4";
        } else if (value == (short) 0x0806) {
            ethtyp = "ARP";
        }
        else if (value == (short) 0x86DD) {
            ethtyp = "IPv6";
        }
        return new EtherPacket(remain, packet.getTimestampS(), packet.getTimestampMS(), packet.isLilendian(),toHexString(dst),toHexString(src),ethtyp );
    }

    public static IPPacket AnalyseIPv4(EtherPacket packet) throws UnknownHostException {
        byte[] data = packet.getData();

        byte firstByte = data[0];
        int version = (firstByte >> 4) & 0x0F;  // Extraire les 4 bits de poids fort (version)
        int ihl = firstByte & 0x0F;  // Extraire les 4 bits de poids faible (IHL)
        int headerLen = ihl*4; //la longueur du header
        byte[] remain = new byte[data.length-headerLen];
        System.arraycopy(data, headerLen -1, remain, 0, remain.length);
        ByteBuffer pr = ByteBuffer.wrap(data,9,1);
        ByteBuffer ipsrc = ByteBuffer.wrap(data,12,4);
        ByteBuffer ipdst = ByteBuffer.wrap(data,16,4);
        if(packet.isLilendian()){
            pr.order(ByteOrder.LITTLE_ENDIAN);
            ipsrc.order(ByteOrder.LITTLE_ENDIAN);
            ipdst.order(ByteOrder.LITTLE_ENDIAN);
        }
        String IPSrc = (InetAddress.getByAddress(ipsrc.array())).getHostAddress();
        String IPDst = (InetAddress.getByAddress(ipdst.array())).getHostAddress();

        return new IPPacket(remain, packet.getTimestampS(), packet.getTimestampMS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(),IPSrc,IPDst,pr.getShort());

    }

    public static IPPacket AnalyseIPv6(EtherPacket packet) throws UnknownHostException {
        byte[] data = packet.getData();
        byte[] payload = new byte[data.length-40];
        System.arraycopy(data, 39, payload, 0, payload.length);
        ByteBuffer srcIP =ByteBuffer.wrap(data,8,16);
        ByteBuffer dstIP = ByteBuffer.wrap(data,24,16);
        ByteBuffer pr = ByteBuffer.wrap(data,6,1);
        if(packet.isLilendian()){
            pr.order(ByteOrder.LITTLE_ENDIAN);
            dstIP.order(ByteOrder.LITTLE_ENDIAN);
            srcIP.order(ByteOrder.LITTLE_ENDIAN);
        }
        String IPSrc = (Inet6Address.getByAddress(srcIP.array())).getHostAddress();
        String IPDst = (Inet6Address.getByAddress(pr.array())).getHostAddress();
        return new IPPacket(payload, packet.getTimestampS(), packet.getTimestampMS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(),IPSrc,IPDst,pr.getShort());
    }

    public static ARPPacket AnalyseARP(EtherPacket packet) throws UnknownHostException {
        byte[] data = packet.getData();
        byte[] data2 = new byte[data.length-28];
        String p = "";
        System.arraycopy(data, 27, data2, 0, data2.length);
        ByteBuffer op = ByteBuffer.wrap(data,6,2);
        ByteBuffer senderMAC = ByteBuffer.wrap(data,8,6);
        ByteBuffer senderIP = ByteBuffer.wrap(data,14,4);
        ByteBuffer destMAC = ByteBuffer.wrap(data,18,6);
        ByteBuffer destIP = ByteBuffer.wrap(data,24,4);
        if(packet.isLilendian()){
            op.order(ByteOrder.LITTLE_ENDIAN);
            senderMAC.order(ByteOrder.LITTLE_ENDIAN);
            senderIP.order(ByteOrder.LITTLE_ENDIAN);
            destMAC.order(ByteOrder.LITTLE_ENDIAN);
            destIP.order(ByteOrder.LITTLE_ENDIAN);
        }
        int pr = op.getShort();
        if (pr == 1){
            p = "request";
        }
        else if (pr == 2){
            p = "reply";
        }
        String sdMAC = toHexString(senderMAC);
        String sdIP = (InetAddress.getByAddress(senderIP.array())).getHostAddress();
        String dstMAC = toHexString(destMAC);
        String dstIP = (InetAddress.getByAddress(destIP.array())).getHostAddress();
        return new ARPPacket(data2, packet.getTimestampS(), packet.getTimestampMS(), packet.isLilendian(), packet.getMACdest(), packet.getMACsrc(), packet.getEtherType(), p,sdMAC,dstMAC,sdIP,dstIP);
    }

    public static ICMPPacket AnalyseICMP(IPPacket packet) {
        byte[] data = packet.getData();
        byte[] data2 = new byte[data.length-8];
        System.arraycopy(data, 7, data2, 0, data2.length);
        ByteBuffer type = ByteBuffer.wrap(data,0,1);
        if (packet.isLilendian()){
            type.order(ByteOrder.LITTLE_ENDIAN);
        }
        return new ICMPPacket(data2, packet.getTimestampS(), packet.getTimestampMS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(), packet.getSourceIP(), packet.getDestinationIP(), packet.getVersion(), type.getShort());
    }

    public static TCPPacket AnalyseTCP(IPPacket packet) {
        byte[] data = packet.getData();
        byte r = data[12];
        int len = (r >> 4) & 0x0F; //prendre la longueur du header
        int length = len*4;
        byte[] data2 = new byte[data.length-length];
        System.arraycopy(data, length-1, data2, 0, data2.length);
        ByteBuffer src = ByteBuffer.wrap(data,0,2);
        ByteBuffer dst = ByteBuffer.wrap(data,2,2);
        ByteBuffer se = ByteBuffer.wrap(data,4,4);
        ByteBuffer ack = ByteBuffer.wrap(data,8,4);
        String f = extractTcpFlags(data[13]);
        if (packet.isLilendian()){
            se.order(ByteOrder.LITTLE_ENDIAN);
            ack.order(ByteOrder.LITTLE_ENDIAN);
            src.order(ByteOrder.LITTLE_ENDIAN);
            dst.order(ByteOrder.LITTLE_ENDIAN);
        }
        return new TCPPacket(data2, packet.getTimestampS(), packet.getTimestampMS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(), packet.getSourceIP(), packet.getDestinationIP(), packet.getVersion(), src.getShort(), dst.getShort(), se.getInt(), ack.getInt(), f);
    }

    public static UDPPacket AnalyseUDP(IPPacket packet) {
        byte[] data = packet.getData();
        byte[] data2 = new byte[data.length-8];
        System.arraycopy(data, 7, data2, 0, data2.length);
        ByteBuffer src = ByteBuffer.wrap(data,0,2);
        ByteBuffer dst = ByteBuffer.wrap(data,2,2);
        if (packet.isLilendian()){
            dst.order(ByteOrder.LITTLE_ENDIAN);
            src.order(ByteOrder.LITTLE_ENDIAN);
        }
        return new UDPPacket(data2, packet.getTimestampS(), packet.getTimestampMS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(), packet.getSourceIP(), packet.getDestinationIP(), packet.getVersion(), src.getShort(), dst.getShort());
    }

    public static HTTPPacket AnalyseHTTP(TCPPacket packet) {
        byte[] data = packet.getData();
        String utf8string = new String(data, java.nio.charset.StandardCharsets.UTF_8);
        return new HTTPPacket(packet.getData(), packet.getTimestampS(), packet.getTimestampMS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(), packet.getSourceIP(), packet.getDestinationIP(), packet.getVersion(), packet.getPortSrc(), packet.getPortDst(), packet.getSeqNb(), packet.getAckNb(), packet.getFlag(), utf8string);
    }

    public static DNSPacket AnalyseDNS(UDPPacket packet) {
        byte[] data = packet.getData();
        byte flag = data[3];
        int f = 0;
        boolean i = (flag & 0x80) != 0;
        if (i){
            f =1;
        }
        byte[] data2 = new byte[data.length-12];
        System.arraycopy(data,11,data2,0,data2.length);
        String utf8string = new String(data2, java.nio.charset.StandardCharsets.UTF_8);
        return new DNSPacket(data, packet.getTimestampS(), packet.getTimestampMS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.etherType, packet.getSourceIP(), packet.getDestinationIP(), packet.getVersion(), packet.getPortSrc(), packet.getPortDst(), f,utf8string);
    }

    //public static QUICPacket AnalyseQUIC(UDPPacket packet) {
        //byte[] data = packet.getData();

    //}

    public static String extractTcpFlags(byte flagsByte) {
        // Convertir le byte en entier
        int flags = flagsByte & 0xFF; // On assure que le byte est traité comme un entier non signé
        String flag = "";
        // Vérifier chaque flag en utilisant des opérations de masquage
        boolean fin = (flags & 0x01) != 0; // Bit 0
        boolean syn = (flags & 0x02) != 0; // Bit 1
        boolean rst = (flags & 0x04) != 0; // Bit 2
        boolean psh = (flags & 0x08) != 0; // Bit 3
        boolean ack = (flags & 0x10) != 0; // Bit 4
        boolean urg = (flags & 0x20) != 0; // Bit 5

        if (fin){
            flag =flag.concat(" fin ");
        }
        if (syn){
            flag =flag.concat(" syn ");
        }
        if (rst){
            flag =flag.concat(" rst ");
        }
        if (psh){
            flag =flag.concat(" psh ");
        }
        if (ack){
            flag =flag.concat(" ack ");
        }
        if (urg){
            flag =flag.concat(" urg ");
        }
        return flag;

    }

    public static String toHexString(ByteBuffer buffer) {
        StringBuilder hexString = new StringBuilder();
        while (buffer.hasRemaining()) {
            byte b = buffer.get();
            hexString.append(String.format("%02X ", b)); // Conversion en hexadécimal avec deux chiffres
        }
        return hexString.toString();
    }

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
