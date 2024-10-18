public class QUICPacket extends UDPPacket{
    private int type;
    private String message;
    public QUICPacket(byte[] data, long timestampS, boolean isend, String Macsource, String Macdest, String ethtype, String sourceIP, String destinationIP, int protocol, int portSrc, int portDst, int type, String message) {
        super(data, timestampS, isend, Macsource, Macdest,ethtype, sourceIP, destinationIP, protocol, portSrc, portDst);
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
