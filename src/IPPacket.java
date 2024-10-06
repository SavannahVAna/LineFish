public class IPPacket extends EtherPacket {
    protected  String sourceIP;
    protected  String destinationIP;
    protected  int version;


    public IPPacket(byte[] data, int timestampS, int timestampMS,  boolean end, String Macsource, String Macdest, String sourceIP, String destinationIP, int protocol) {
        super(data, timestampS, timestampMS,  end, Macsource, Macdest);
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.version = protocol;
    }
    public String getSourceIP() {
        return sourceIP;
    }
    public String getDestinationIP() {
        return destinationIP;
    }
    public int getVersion() {
        return version;
    }
}
