import javax.swing.*;

public class DHCPPacket extends UDPPacket{
    private int op;
    private String yaddr;
    public DHCPPacket(byte[] data, int timestampS, int timestampMS, boolean isend, String Macsource, String Macdest, String ethtype, String sourceIP, String destinationIP, int protocol, int portSrc, int portDst, int ope, String yaddr) {
        super(data, timestampS, timestampMS, isend, Macsource, Macdest, ethtype, sourceIP, destinationIP, protocol, portSrc, portDst);
        this.op = ope;
        this.yaddr = yaddr;
    }
    public int getOp() {
        return op;
    }
    public String getYaddr() {
        return yaddr;
    }
    public String toString(){
        String a = "";
        if(op==1){
            a = "request";
        }
        else if(op==2){
            a = "response";
        }
        if(!yaddr.equals("0.0.0.0")){
            return (this.getSourceIP() +" " +this.getDestinationIP() + " DHCP " + a + " address given " + yaddr);
        }
        else{
            return (this.getSourceIP() + " " + this.getDestinationIP()) + " DHCP " + a;
        }
    }
}
