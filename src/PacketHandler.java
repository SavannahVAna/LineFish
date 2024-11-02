import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class PacketHandler {
    public static EtherPacket AnalyseEther(Packet packet) {
        byte[] data = packet.getData();
        //prend ce qui va etre la nouvelle partie data dans la frame ethernet
        byte[] remainder = new byte[data.length-14];
        System.arraycopy(data, 14, remainder, 0, remainder.length);
        int o = remainder.length;
        int c = 0;
        while (remainder[o-1] == 0){
            o--;
            c++;
        }
        byte[] remain = new byte[remainder.length-c];
        System.arraycopy(remainder, 0, remain, 0, remain.length);
        //puis les futurs attributs de la classe Etherpacket
        ByteBuffer dst = ByteBuffer.wrap(data, 0,6);
        ByteBuffer src = ByteBuffer.wrap(data,6,6);
        ByteBuffer t = ByteBuffer.wrap(data,12,2);

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
        return new EtherPacket(remain, packet.getTimestampS(), packet.isLilendian(),toHexString(dst),toHexString(src),ethtyp );
    }

    public static IPPacket AnalyseIPv4(EtherPacket packet) throws UnknownHostException {
        byte[] data = packet.getData();

        byte firstByte = data[0];
        int version = (firstByte >> 4) & 0x0F;  // Extraire les 4 bits de poids fort (version)
        int ihl = firstByte & 0x0F;  // Extraire les 4 bits de poids faible (IHL)
        int headerLen = ihl*4; //la longueur du header
        byte[] remain = new byte[data.length-headerLen];
        System.arraycopy(data, headerLen , remain, 0, remain.length);
        byte[] pri = {0x0000 , data[9]};
        ByteBuffer pr = ByteBuffer.wrap(pri);
        byte[] ipsrc  = new byte[4];
        byte[] ipdst  = new byte[4];
        System.arraycopy(data, 12, ipsrc,0  , 4);
        System.arraycopy(data, 16, ipdst,0  , 4);

        //if(packet.isLilendian()){
        //    pr.order(ByteOrder.LITTLE_ENDIAN);
        //    ipsrc.order(ByteOrder.LITTLE_ENDIAN);
        //    ipdst.order(ByteOrder.LITTLE_ENDIAN);
        //}

        String IPSrc = (InetAddress.getByAddress(ipsrc)).getHostAddress();
        String IPDst = (InetAddress.getByAddress(ipdst)).getHostAddress();

        return new IPPacket(remain, packet.getTimestampS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(),IPSrc,IPDst,pr.getShort());

    }

    public static IPPacket AnalyseIPv6(EtherPacket packet) throws UnknownHostException {
        byte[] data = packet.getData();
        byte[] payload = new byte[data.length-40];
        System.arraycopy(data, 40, payload, 0, payload.length);

        byte[] ipsrc  = new byte[16];
        byte[] ipdst  = new byte[16];
        System.arraycopy(data, 24, ipdst , 0, 16);
        System.arraycopy(data, 8, ipsrc , 0, 16);
        byte[] pri = {0x0000 , data[6]};
        ByteBuffer pr = ByteBuffer.wrap(pri);
        //if(packet.isLilendian()){
        //    pr.order(ByteOrder.LITTLE_ENDIAN);
        //    dstIP.order(ByteOrder.LITTLE_ENDIAN);
        //    srcIP.order(ByteOrder.LITTLE_ENDIAN);
        //}
        String IPSrc = (Inet6Address.getByAddress(ipsrc)).getHostAddress();
        String IPDst = (Inet6Address.getByAddress(ipdst)).getHostAddress();
        return new IPPacket(payload, packet.getTimestampS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(),IPSrc,IPDst,pr.getShort());
    }

    public static ARPPacket AnalyseARP(EtherPacket packet) throws UnknownHostException {
        byte[] data = packet.getData();
        byte[] data2 = new byte[data.length - 28];
        System.arraycopy(data, 27, data2, 0, data2.length);

        // Opération (ARP request = 1, reply = 2) -> data[6] et data[7]
        int pr = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
        String p = (pr == 1) ? "request" : (pr == 2) ? "reply" : "unknown";

        // Adresse MAC source (6 octets à partir de data[8])
        String sdMAC = toHexString(Arrays.copyOfRange(data, 8, 14));

        // Adresse IP source (4 octets à partir de data[14])
        String sdIP = InetAddress.getByAddress(Arrays.copyOfRange(data, 14, 18)).getHostAddress();

        // Adresse MAC destination (6 octets à partir de data[18])
        String dstMAC = toHexString(Arrays.copyOfRange(data, 18, 24));

        // Adresse IP destination (4 octets à partir de data[24])
        String dstIP = InetAddress.getByAddress(Arrays.copyOfRange(data, 24, 28)).getHostAddress();

        return new ARPPacket(data2, packet.getTimestampS(), packet.isLilendian(),
                packet.getMACdest(), packet.getMACsrc(), packet.getEtherType(),
                p, sdMAC, dstMAC, sdIP, dstIP);
    }


    public static ICMPPacket AnalyseICMP(IPPacket packet) {
        byte[] data = packet.getData();
        byte[] data2 = new byte[data.length-8];
        System.arraycopy(data, 7, data2, 0, data2.length);
        byte[] ty = {0x0000 , data[0]};
        ByteBuffer type = ByteBuffer.wrap(ty);
        //if (packet.isLilendian()){
        //    type.order(ByteOrder.LITTLE_ENDIAN);
        //}
        return new ICMPPacket(data2, packet.getTimestampS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(), packet.getSourceIP(), packet.getDestinationIP(), packet.getProtocol(), type.getShort());
    }

    public static boolean isFTP(TCPPacket packet) {
        try{
            byte[] data = packet.getData();
            byte r = data[12];
            int len = (r >> 4) & 0x0F; //prendre la longueur du header
            int length = len*4;
            byte[] data2 = new byte[data.length-length];
            System.arraycopy(data, length, data2, 0, data2.length);
            String utf8string = new String(data2, java.nio.charset.StandardCharsets.UTF_8);
            String[] comms = {"USER", "PASS", "QUIT",  "CWD", "PWD", "LIST", "RETR", "STOR", "DELE", "TYPE", "MKD", "RMD", "PORT", "PASV", "NOOP"};
            for(String comm : comms){
                if(utf8string.contains(comm)){
                    return true;
                }
            }
            String[] codes = {"110", "120", "125", "150", "200", "202", "211", "212", "213", "214", "215", "220", "221", "225", "226", "227", "230", "250", "257", "331", "332", "350", "421", "425", "426", "450", "451","452", "500","501", "502", "503", "504", "530", "532", "550", "551", "552", "553"};
            for(String code : codes){
                if(utf8string.startsWith(code)){
                    return true;
                }
            }
            return false;
        }
        catch(Exception e){
            return false;
        }
    }

    public static TCPPacket AnalyseTCP(IPPacket packet) {
        byte[] data = packet.getData();

        // Lecture des ports source et destination (2 octets chacun)
        ByteBuffer buffer = ByteBuffer.wrap(data);

        // Port source (octets 0-1)
        int srcPort = buffer.getShort() & 0xFFFF; // Utiliser & 0xFFFF pour obtenir un entier non signé
        // Port destination (octets 2-3)
        int dstPort = buffer.getShort() & 0xFFFF; // Utiliser & 0xFFFF pour obtenir un entier non signé

        // Lecture des numéros de séquence et d'accusé de réception (4 octets chacun)
        int seqNumber = buffer.getInt(); // Octets 4-7
        int ackNumber = buffer.getInt(); // Octets 8-11

        // Lecture des flags TCP (octet 13)
        String flags = extractTcpFlags(data[13]);

        // Création et retour du paquet TCP
        return new TCPPacket(data,
                packet.getTimestampS(),
                packet.isLilendian(),
                packet.getMACsrc(),
                packet.getMACdest(),
                packet.getEtherType(),
                packet.getSourceIP(),
                packet.getDestinationIP(),
                packet.getProtocol(),
                srcPort,
                dstPort,
                seqNumber,
                ackNumber,
                flags);
    }


    public static UDPPacket AnalyseUDP(IPPacket packet) {
        byte[] data = packet.getData();
        byte[] data2 = new byte[data.length-8];
        System.arraycopy(data, 7, data2, 0, data2.length);
        ByteBuffer buffer = ByteBuffer.wrap(data);

        // Port source (octets 0-1)
        int srcPort = buffer.getShort() & 0xFFFF; // Utiliser & 0xFFFF pour obtenir un entier non signé
        // Port destination (octets 2-3)
        int dstPort = buffer.getShort() & 0xFFFF; // Uti
        //if (packet.isLilendian()){
        //    dst.order(ByteOrder.LITTLE_ENDIAN);
        //    src.order(ByteOrder.LITTLE_ENDIAN);
        //}
        return new UDPPacket(data2, packet.getTimestampS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(), packet.getSourceIP(), packet.getDestinationIP(), packet.getProtocol(), srcPort, dstPort);
    }

    public static HTTPPacket AnalyseHTTP(TCPPacket packet) {
        byte[] data = packet.getData();
        byte r = data[12];
        int len = (r >> 4) & 0x0F; //prendre la longueur du header
        int length = len*4;
        byte[] data2 = new byte[data.length-length];
        System.arraycopy(data, length, data2, 0, data2.length);
        String utf8string = new String(data2, java.nio.charset.StandardCharsets.UTF_8);
        return new HTTPPacket(packet.getData(), packet.getTimestampS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(), packet.getSourceIP(), packet.getDestinationIP(), packet.getProtocol(), packet.getPortSrc(), packet.getPortDst(), packet.getSeqNb(), packet.getAckNb(), packet.getFlag(), utf8string);
    }

    public static boolean testHTTP(TCPPacket packet) {
        try{
            byte[] data = packet.getData();
            byte r = data[12];
            int len = (r >> 4) & 0x0F; //prendre la longueur du header
            int length = len*4;
            byte[] data2 = new byte[data.length-length];
            System.arraycopy(data, length, data2, 0, data2.length);
            String utf8string = new String(data2, java.nio.charset.StandardCharsets.UTF_8);
            if(utf8string.toUpperCase().contains("HTTP")) {
                return true;
            }
            else {
                return false;
            }
        }
        catch(Exception e){
            return false;
        }
    }

    public static FTPPacket AnalyseFTP(TCPPacket packet) {
        byte[] data = packet.getData();
        byte r = data[12];
        int len = (r >> 4) & 0x0F; //prendre la longueur du header
        int length = len*4;
        byte[] data2 = new byte[data.length-length];
        System.arraycopy(data, length, data2, 0, data2.length);
        String utf8string = new String(data2, java.nio.charset.StandardCharsets.UTF_8);
        return new FTPPacket(packet.getData(), packet.getTimestampS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(), packet.getSourceIP(), packet.getDestinationIP(), packet.getProtocol(), packet.getPortSrc(), packet.getPortDst(), packet.getSeqNb(), packet.getAckNb(), packet.getFlag(), utf8string);
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
        return new DNSPacket(data, packet.getTimestampS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.etherType, packet.getSourceIP(), packet.getDestinationIP(), packet.getProtocol(), packet.getPortSrc(), packet.getPortDst(), f,utf8string);
    }

    public static boolean isDNS(UDPPacket packet) {
        byte[] data = packet.getData();

        // Assurez-vous que les données contiennent au moins 4 octets
        if (data.length < 4) {
            return false; // Pas assez de données pour vérifier
        }

        ByteBuffer buffer = ByteBuffer.wrap(data);

        // Les flags DNS se trouvent aux octets 2 et 3
        short flags = buffer.getShort(3); // Récupérer les deux octets à partir de l'index 2 for some reason tha data is not cut correctly and there is still one byte that is part od the udp segment first

        return (flags == (short) 0x8180 || flags == (short) 0x0100); // Vérifier si c'est une réponse ou query standard (ce sont les valeurs les plus courantes des flags
    }

    public static QUICPacket AnalyseQUIC(UDPPacket packet) {
        byte[] data = packet.getData();
        String type ="" ;
        int ver;
        boolean bit7IsOne = (data[1] & 0b10000000) != 0;
        boolean isSixthBitSet = (data[1] & 0b00100000) != 0;
        if(bit7IsOne && isSixthBitSet) {
            byte[] version = {data[2] , data[3], data[4] , data[5] };
            ByteBuffer vrs = ByteBuffer.wrap(version);
            int maskedBits = (data[1] & 0b00001110) >> 2;
            ver =  vrs.getInt();
            type = switch (maskedBits) {
                case 0 -> "initial";
                case 1 -> "RTT";
                case 2 -> "Handshake";
                case 3 -> "Retry";
                default -> type;
            };
        } else if (isSixthBitSet) {
            type = "short";
            ver = 0;
        }
        return new QUICPacket(data, packet.getTimestampS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(), packet.getSourceIP(), packet.getDestinationIP(), packet.getProtocol(), packet.getPortSrc(), packet.getPortDst(), type);
    }

    public static boolean isQUIC(UDPPacket packet) {
        if(packet.getPortSrc() == 443 || packet.getPortDst() == 443){
            byte[] data = packet.getData();
            boolean isSixthBitSet = (data[1] & 0b00100000) != 0;
            if(isSixthBitSet){
                boolean bit7IsOne = (data[1] & 0b10000000) != 0;
                if(bit7IsOne) {
                    byte[] version = {data[2], data[3], data[4], data[5]};
                    ByteBuffer vrs = ByteBuffer.wrap(version);
                    int v = vrs.getInt();
                    if (v == 1 || v == 1362113840) {
                        return true;
                    }
                    return true;
                }
                return true;
            }
            return false;
        }
        return false;
    }

    public static boolean isQUICS(UDPPacket packet) {
        byte[] data = packet.getData();
        byte[] version = {data[2], data[3], data[4], data[5]};
        ByteBuffer vrs = ByteBuffer.wrap(version);
        int v = vrs.getInt();
        if (v == 1 || v == 1362113840) {
            return true;
        }
        else {
            return false;
        }
    }

    public static DHCPPacket AnalyseDHCP(UDPPacket packet) throws UnknownHostException {
        byte[] data = packet.getData();
        int op = data[1];
        byte[] iaddress = new byte[4];
        System.arraycopy(data,17,iaddress,0,4);
        String givenIP = (InetAddress.getByAddress(iaddress)).getHostAddress();
        return new DHCPPacket(data,packet.getTimestampS(), packet.isLilendian(), packet.getMACsrc(), packet.getMACdest(), packet.getEtherType(), packet.getSourceIP(), packet.getDestinationIP(), packet.getProtocol(), packet.getPortSrc(), packet.getPortDst(), op,givenIP);
    }

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

    public static String toHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X ", b)); // Conversion en hexadécimal avec deux chiffres
        }
        return hexString.toString().trim();
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

    public static void printOtherpacket(EtherPacket packet) {
        byte[] packetData = packet.getData();
        ByteBuffer buffer = ByteBuffer.wrap(packetData);
        StringBuilder hexString = new StringBuilder();
        while (buffer.hasRemaining()) {
            byte b = buffer.get();
            hexString.append(String.format("%02X ", b)); // Conversion en hexadécimal avec deux chiffres
        }
        System.out.println(hexString);
    }

    public static boolean isDHCP(UDPPacket packet) {//dans DHCP ya plein de zéros au milieu donc on teste ça
        byte[] data = packet.getData();
        int n = 0;
        for(byte b : data){
            if(b==0x00){
                n++;
            }
            else {
                n =0;
            }
            if(n==192){
                return true;
            }
        }
        return false;
    }
}
