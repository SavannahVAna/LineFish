public class TCPPacket extends IPPacket {
    protected  int portSrc;
    protected  int portDst;
    protected  int seqNb;
    protected  String flag;
    protected  int ackNb;
    public TCPPacket(byte[] data, long timestampS, boolean isend, String Macsource, String Macdest, String ethtype, String sourceIP, String destinationIP, int protocol, int portSrc, int portDst, int seqNb, int ack, String flag) {
        super(data, timestampS, isend,Macsource, Macdest, ethtype,sourceIP, destinationIP, protocol);
        this.portSrc = portSrc;
        this.portDst = portDst;
        this.seqNb = seqNb;
        this.flag = flag;
        this.ackNb = ack;
    }
    public int getPortSrc() {
        return portSrc;
    }

    public int getPortDst() {
        return portDst;
    }

    public int getSeqNb() {
        return seqNb;
    }
    public String getFlag() {
        return flag;
    }
    public int getAckNb() {
        return ackNb;
    }

    public String toString() {
        return this.getSourceIP() + " " + this.getDestinationIP() + " TCP " + this.portSrc + " -> " + this.portDst + " " + this.flag ;
    }
}
