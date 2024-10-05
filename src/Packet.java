public class Packet {
    private byte[] data;
    private int timestampS;
    private int timestampMS;
    public Packet(byte[] data, int timestampS, int timestampMS) {
        this.data = data;
        this.timestampS = timestampS;
        this.timestampMS = timestampMS;
    }
}
