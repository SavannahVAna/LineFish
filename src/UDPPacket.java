public class UDPPacket extends IPPacket {
    protected  int portSrc;
    protected  int portDst;
    public UDPPacket(byte[] data, int timestampS, int timestampMS, boolean isend, String Macsource, String Macdest,String ethtype, String sourceIP, String destinationIP, int protocol, int portSrc, int portDst) {
        super(data, timestampS, timestampMS, isend, Macsource, Macdest, ethtype,sourceIP, destinationIP, protocol);
        this.portSrc = portSrc;
        this.portDst = portDst;
    }
    public int getPortSrc() {
        return portSrc;
    }
    public int getPortDst() {
        return portDst;
    }

    public String toString() {
        return this.getSourceIP() + " " + this.getDestinationIP() + " UDP " + this.portSrc + " -> " + this.portDst ;
    }
}
