public class EtherPacket extends Packet {
    protected  String MACdest;
    protected  String MACsrc;
    public EtherPacket(byte[] data, int timestampS, int timestampMS,boolean isendan, String MACdest, String MACsrc) {
        super(data, timestampS, timestampMS, isendan);
        this.MACdest = MACdest;
        this.MACsrc = MACsrc;
    }
    public String getMACdest() {
        return MACdest;
    }
    public String getMACsrc() {
        return MACsrc;
    }
}
