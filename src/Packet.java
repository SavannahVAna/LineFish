public class Packet {
    protected byte[] data;
    protected  int timestampS;
    protected  int timestampMS;
    protected final boolean islilendian;

    public Packet(byte[] data, int timestampS, int timestampMS, boolean islilendian) {
        this.data = data;
        this.timestampS = timestampS;
        this.timestampMS = timestampMS;
        this.islilendian = islilendian;
    }

    public byte[] getData() { return data; }
    public int getTimestampS() { return timestampS; }
    public int getTimestampMS() { return timestampMS; }
    public boolean isLilendian() { return islilendian; }
}