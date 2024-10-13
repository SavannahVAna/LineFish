public class IPPacket extends EtherPacket {
    protected  String sourceIP;
    protected  String destinationIP;
    protected  int protocol;


    public IPPacket(byte[] data, int timestampS, int timestampMS,  boolean end, String Macsource, String Macdest, String ethertype, String sourceIP, String destinationIP, int protocol) {
        super(data, timestampS, timestampMS,  end, Macsource, Macdest,ethertype);
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.protocol = protocol;
    }
    public String getSourceIP() {
        return sourceIP;
    }
    public String getDestinationIP() {
        return destinationIP;
    }
    public int getProtocol() {
        return protocol;
    }
    public String toString() {
        return sourceIP + " " + destinationIP ;
    }
}
