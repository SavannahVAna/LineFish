public class HTTPPacket extends TCPPacket{
    private String message;
    public HTTPPacket(byte[] data, long timestampS, boolean ised, String Macsource, String Macdest, String etherType, String sourceIP, String destinationIP, int protocol, int portSrc, int portDst, int seqNb, int ack, String flag, String message) {
        super(data, timestampS, ised, Macsource, Macdest, etherType,sourceIP, destinationIP, protocol, portSrc, portDst, seqNb, ack, flag);
        this.message = message;
    }
    public String getMessage() {
        return message;
    }
    public String toString(){
        return (this.getSourceIP()+ " " + this.getDestinationIP() + " HTTP " +this.getMessage());
    }
}
