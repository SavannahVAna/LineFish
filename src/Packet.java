public abstract class Packet {
    protected byte[] data;
    protected  int timestampS;
    protected  int timestampMS;

    public Packet(byte[] data, int timestampS, int timestampMS) {
        this.data = data;
        this.timestampS = timestampS;
        this.timestampMS = timestampMS;
    }

    public byte[] getData() { return data; }
    public int getTimestampS() { return timestampS; }
    public int getTimestampMS() { return timestampMS; }
}