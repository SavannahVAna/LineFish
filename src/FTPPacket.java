public class FTPPacket extends TCPPacket {
    private String command;
    public FTPPacket(byte[] data, int timestampS, int timestampMS, boolean isend, String Macsource, String Macdest, String ethtype, String sourceIP, String destinationIP, int protocol, int portSrc, int portDst, int seqNb, int ack, String flag, String command) {
        super(data, timestampS, timestampMS, isend, Macsource, Macdest, ethtype, sourceIP, destinationIP, protocol, portSrc, portDst, seqNb, ack, flag);
        this.command = command;
    }
    public String getCommand() {
        return command;
    }
}
