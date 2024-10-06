public class QUICPacket extends UDPPacket{
    private int type;
    private String message;
    public QUICPacket(byte[] data, int timestampS, int timestampMS, boolean isend, String Macsource, String Macdest, String sourceIP, String destinationIP, int protocol, int portSrc, int portDst, int type,  String message) {
        super(data, timestampS, timestampMS, isend, Macsource, Macdest, sourceIP, destinationIP, protocol, portSrc, portDst);
        this.type = type;
        this.message = message;
    }
    public int getType() {
        return type;
    }
    public String getMessage() {
        return message;
    }
}
