public class ARPPacket extends EtherPacket{
    private String operation;
    private String sendhardaddr;
    private String receivehardaddr;
    private String sendip;
    private String receiveip;
    public ARPPacket(byte[] data, long timestampS, boolean isendian, String MACdest, String MACsrc, String etherType, String operation, String sendhardaddr, String receivehardaddr, String sendip, String receiveip) {
        super(data, timestampS, isendian,MACdest, MACsrc, etherType);
        this.operation = operation;
        this.sendhardaddr = sendhardaddr;
        this.receivehardaddr = receivehardaddr;
        this.sendip = sendip;
        this.receiveip = receiveip;
    }
    public String getOperation() {
        return operation;
    }
    public String getSendhardaddr() {
        return sendhardaddr;
    }
    public String getReceivehardaddr() {
        return receivehardaddr;
    }
    public String getSendip() {
        return sendip;
    }
    public String getReceiveip() {
        return receiveip;
    }
}
