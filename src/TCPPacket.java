public class TCPPacket extends IPPacket {
    protected  int portSrc;
    protected  int portDst;
    protected  int seqNb;
    protected  String flag;
    public TCPPacket(byte[] data, int timestampS, int timestampMS, boolean isend, String Macsource, String Macdest, String sourceIP, String destinationIP, int protocol, int portSrc, int portDst, int seqNb, String flag) {
        super(data, timestampS, timestampMS, isend,Macsource, Macdest, sourceIP, destinationIP, protocol);
        this.portSrc = portSrc;
        this.portDst = portDst;
        this.seqNb = seqNb;
        this.flag = flag;
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
}
