public class Packet {
    protected byte[] data;
    protected long timestampS;
    //protected  int timestampMS;
    protected final boolean islilendian;

    public Packet(byte[] data, long timestampS, boolean islilendian) {
        this.data = data;
        this.timestampS = timestampS ;
        //this.timestampMS = timestampMS;
        this.islilendian = islilendian;
    }

    public byte[] getData() { return data; }
    public long getTimestampS() { return timestampS; }
    //public int getTimestampMS() { return timestampMS; }
    public boolean isLilendian() { return islilendian; }
}