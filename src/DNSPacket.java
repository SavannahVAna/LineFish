public class DNSPacket extends UDPPacket {
    private int QR;
    private String message;
    public DNSPacket(byte[] data, long timestampS, boolean isendian, String Macsource, String Macdest, String etherType, String sourceIP, String destinationIP, int protocol, int portSrc, int portDst, int QR, String message) {
        super(data, timestampS, isendian, Macsource, Macdest, etherType, sourceIP, destinationIP, protocol, portSrc, portDst);
        this.QR = QR;
        this.message = message;
    }
    public int getQR() {
        return QR;
    }
    public String getMessage() {
        return message;
    }
    public String toString() {
        return this.getSourceIP() + " " +this.getDestinationIP() + " DNS " + QR + " message=" + message ;
    }
}
