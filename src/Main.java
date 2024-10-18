import java.io.FileNotFoundException;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class Main {
    public static void main(String[] args) {
        PcapReader reader = new PcapReader();

        try {
            double t;
            long ti;
            int n = 0;
            ArrayList<Packet> packetList = reader.openPcap("C:\\Users\\savpo\\Downloads\\tcp-ecn-sample.pcap");
            ArrayList<EtherPacket> etherlist = new ArrayList<EtherPacket>();
            for (Packet packet : packetList) {
                etherlist.add(PacketHandler.AnalyseEther(packet));
            }
            long time = etherlist.getFirst().getTimestampS();

            System.out.println("nb time  source   destination   protocol");
            for (EtherPacket packet : etherlist) {
                ti = packet.getTimestampS() -time;
                t = ti/1000000.0;
                if (packet.etherType.equals("ARP")) {
                    ARPPacket arpPacket = PacketHandler.AnalyseARP(packet);

                    System.out.println(n + " " + t  +" " + arpPacket);
                }
                else if (packet.etherType.equals("IPv4")) {
                    IPPacket ipPacket = PacketHandler.AnalyseIPv4(packet);
                    switch (ipPacket.getProtocol()){
                        case 1 :
                            ICMPPacket icmpPacket = PacketHandler.AnalyseICMP(ipPacket);


                            System.out.println(n + " " + t +  " " + icmpPacket);
                            break;
                        case 6 :
                            TCPPacket tcpPacket = PacketHandler.AnalyseTCP(ipPacket);
                            if (tcpPacket.getPortDst() == 80 || tcpPacket.getPortSrc() == 80 || tcpPacket.getPortDst() == 8080 || tcpPacket.getPortSrc() == 8080) {
                                try {
                                    HTTPPacket httpPacket = PacketHandler.AnalyseHTTP(tcpPacket);

                                    System.out.println(n + " " + t  + " " +httpPacket);
                                } catch (Exception e) {


                                    System.out.println(n + " " + t + " " +tcpPacket);
                                }

                            }
                            else {

                                System.out.println(n + " " + t +  " " +tcpPacket);
                            }
                            break;
                            //TODO implement FTP
                        case 17 :
                            UDPPacket udpPacket = PacketHandler.AnalyseUDP(ipPacket);
                            if(udpPacket.getPortDst() == 53 || udpPacket.getPortSrc() == 53){
                                DNSPacket dnsPacket = PacketHandler.AnalyseDNS(udpPacket);


                                System.out.println(n + " " + t +  " " +dnsPacket);
                            }
                            else if(udpPacket.getPortSrc() == 67 || udpPacket.getPortDst() == 67 || udpPacket.getPortSrc() == 68 || udpPacket.getPortDst() == 68){
                                DHCPPacket dhcpPacket = PacketHandler.AnalyseDHCP(udpPacket);


                                System.out.println(n + " " + t  + " " +dhcpPacket);
                            }
                            //TODO implement QUIC
                            else {


                                System.out.println(n + " " + t  + " " +udpPacket);
                            }
                            break;
                        default :

                            System.out.println(n + " " + t  + " " +ipPacket);
                    }
                }
                else if (packet.etherType.equals("IPv6")) {
                    IPPacket ipPacket = PacketHandler.AnalyseIPv6(packet);
                    switch (ipPacket.getProtocol()){
                        case 1 :
                            ICMPPacket icmpPacket = PacketHandler.AnalyseICMP(ipPacket);

                            System.out.println(n + " " + t +  " " +icmpPacket);
                            break;
                        case 6 :
                            TCPPacket tcpPacket = PacketHandler.AnalyseTCP(ipPacket);
                            if (tcpPacket.getPortDst() == 80 || tcpPacket.getPortSrc() == 80 || tcpPacket.getPortDst() == 8080 || tcpPacket.getPortSrc() == 8080) {
                                HTTPPacket httpPacket = PacketHandler.AnalyseHTTP(tcpPacket);


                                System.out.println(n + " " + t  + " " +httpPacket);
                            }
                            else {

                                System.out.println(n + " " + t  + " " +tcpPacket);
                            }
                            break;
                        //TODO implement FTP
                        case 17 :
                            UDPPacket udpPacket = PacketHandler.AnalyseUDP(ipPacket);
                            if(udpPacket.getPortDst() == 53 || udpPacket.getPortSrc() == 53){
                                DNSPacket dnsPacket = PacketHandler.AnalyseDNS(udpPacket);

                                System.out.println(n + " " + t  + " " +dnsPacket);
                            }
                            else if(udpPacket.getPortSrc() == 67 || udpPacket.getPortDst() == 67 || udpPacket.getPortSrc() == 68 || udpPacket.getPortDst() == 68){
                                DHCPPacket dhcpPacket = PacketHandler.AnalyseDHCP(udpPacket);

                                System.out.println(n + " " + t  + " " +dhcpPacket);
                            }
                            //TODO implement QUIC
                            else {


                                System.out.println(n + " " + t  + " " +udpPacket);
                            }
                            break;
                        default :


                            System.out.println(n + " " + t  + " " +ipPacket);
                    }
                }
                n++;
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }

    }

}
