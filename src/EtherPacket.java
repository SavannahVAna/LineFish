public class EtherPacket extends Packet {
    protected  String MACdest;
    protected  String MACsrc;
    protected String etherType;
    public EtherPacket(byte[] data, long timestampS, boolean isendan, String MACdest, String MACsrc, String etherType) {
        super(data, timestampS, isendan);
        this.MACdest = MACdest;
        this.MACsrc = MACsrc;
        this.etherType = etherType;
    }
    public String getMACdest() {
        return MACdest;
    }
    public String getMACsrc() {
        return MACsrc;
    }
    public String getEtherType() {
        return etherType;
    }

    public String toString() {
        return (getMACdest() + " " + getMACsrc() + " " + getEtherType() );
    }
}
