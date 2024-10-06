public class ICMPPacket extends IPPacket {
    private int type;
    public ICMPPacket(byte[] data, int timestampS, int timestampMS, String Macsource, String Macdest, String sourceIP, String destinationIP, int protocol, int type) {
        super(data, timestampS, timestampMS, Macsource, Macdest, sourceIP, destinationIP, protocol);
        this.type = type;
    }
    public int getType() {
        return type;
    }
}
