public class HTTPPacket extends TCPPacket{
    private String message;
    public HTTPPacket(byte[] data, int timestampS, int timestampMS, String Macsource, String Macdest, String sourceIP, String destinationIP, int protocol, int portSrc, int portDst, int seqNb, String flag, String message) {
        super(data, timestampS, timestampMS, Macsource, Macdest, sourceIP, destinationIP, protocol, portSrc, portDst, seqNb, flag);
        this.message = message;
    }
    public String getMessage() {
        return message;
    }
}
