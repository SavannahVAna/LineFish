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
            String filename;
            if(args.length == 0){
                filename = "C:\\Users\\savpo\\Downloads\\pcaps\\pcaps\\tcp.pcap"; //for debugging purposes
            }
            else {
                filename = args[0];
            }
            ArrayList<Packet> packetList = reader.openPcap(filename);
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
                            else if(tcpPacket.getPortDst() == 21 || tcpPacket.getPortDst() ==20 || tcpPacket.getPortSrc() == 20 || tcpPacket.getPortSrc() == 21){
                                try{
                                FTPPacket ftpPacket = PacketHandler.AnalyseFTP(tcpPacket);
                                System.out.println(n + " " + t  + " " +ftpPacket);}
                                catch (NegativeArraySizeException e){
                                    System.out.println(n + " " + t + " " +tcpPacket);
                                }
                            }
                            else {

                                System.out.println(n + " " + t +  " " +tcpPacket);
                            }

                            break;

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
                            else if (PacketHandler.isQUIC(udpPacket)) {
                                QUICPacket quicPacket = PacketHandler.AnalyseQUIC(udpPacket);
                                System.out.println(n + " " + t  + " " +quicPacket);}
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
                            if (tcpPacket.getPortDst() == 80 || tcpPacket.getPortSrc() == 80 || tcpPacket.getPortDst() == 8080 || tcpPacket.getPortSrc() == 8080 || PacketHandler.testHTTP(tcpPacket)) {
                                HTTPPacket httpPacket = PacketHandler.AnalyseHTTP(tcpPacket);


                                System.out.println(n + " " + t  + " " +httpPacket);
                            }
                            else if(tcpPacket.getPortDst() == 21 || tcpPacket.getPortDst() ==20 || tcpPacket.getPortSrc() == 20 || tcpPacket.getPortSrc() == 21){
                                try{
                                    FTPPacket ftpPacket = PacketHandler.AnalyseFTP(tcpPacket);
                                    System.out.println(n + " " + t  + " " +ftpPacket);}
                                catch (NegativeArraySizeException e){
                                    System.out.println(n + " " + t + " " +tcpPacket);
                                }
                            }
                            else {

                                System.out.println(n + " " + t  + " " +tcpPacket);
                            }
                            break;
                        case 17 :
                            UDPPacket udpPacket = PacketHandler.AnalyseUDP(ipPacket);
                            if(udpPacket.getPortDst() == 53 || udpPacket.getPortSrc() == 53){
                                DNSPacket dnsPacket = PacketHandler.AnalyseDNS(udpPacket);

                                System.out.println(n + " " + t  + " " +dnsPacket);
                            }
                            else if(udpPacket.getPortSrc() == 67 || udpPacket.getPortDst() == 67 || udpPacket.getPortSrc() == 68 || udpPacket.getPortDst() == 68){
                                DHCPPacket dhcpPacket = PacketHandler.AnalyseDHCP(udpPacket);

                                System.out.println(n + " " + t  + " " +dhcpPacket);
                            } else if (PacketHandler.isQUIC(udpPacket)) {
                                QUICPacket quicPacket = PacketHandler.AnalyseQUIC(udpPacket);
                                System.out.println(n + " " + t  + " " +quicPacket);
                            } else {


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
