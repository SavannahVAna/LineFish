public class QUICPacket extends UDPPacket{
    private String type;
    //private String message;
    public QUICPacket(byte[] data, long timestampS, boolean isend, String Macsource, String Macdest, String ethtype, String sourceIP, String destinationIP, int protocol, int portSrc, int portDst, String type) {
        super(data, timestampS, isend, Macsource, Macdest,ethtype, sourceIP, destinationIP, protocol, portSrc, portDst);
        this.type = type;
        //this.message = message;
    }
    public String getType() {
        return type;
    }

    public String toString(){
        return this.getSourceIP() + " " + this.getDestinationIP() + " QUIC " + this.portSrc + " -> " + this.portDst + " type: " + this.type;
    }

}
