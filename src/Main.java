import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        PcapReader reader = new PcapReader();

        try {
            int t;
            int ts;
            int n = 0;
            ArrayList<Packet> packetList = reader.openPcap("C:\\Users\\savpo\\Downloads\\tcp-ecn-sample.pcap");
            ArrayList<EtherPacket> etherlist = new ArrayList<EtherPacket>();
            for (Packet packet : packetList) {
                etherlist.add(PacketHandler.AnalyseEther(packet));
            }
            int time = etherlist.getFirst().getTimestampS();
            int timeM = etherlist.getFirst().getTimestampMS();
            System.out.println("nb time  source   destination   protocol");
            for (EtherPacket packet : etherlist) {
                if (packet.etherType.equals("ARP")) {
                    ARPPacket arpPacket = PacketHandler.AnalyseARP(packet);
                    t = arpPacket.getTimestampS() - time;
                    ts = arpPacket.getTimestampMS() - timeM;
                    System.out.println(n + " " + t + "." + ts +" " + arpPacket);
                }
                else if (packet.etherType.equals("IPv4")) {
                    IPPacket ipPacket = PacketHandler.AnalyseIPv4(packet);
                    switch (ipPacket.getProtocol()){
                        case 1 :
                            ICMPPacket icmpPacket = PacketHandler.AnalyseICMP(ipPacket);
                            t = icmpPacket.getTimestampS() - time;
                            ts = icmpPacket.getTimestampMS() - timeM;
                            System.out.println(n + " " + t + "." + ts + " " + icmpPacket);
                            break;
                        case 6 :
                            TCPPacket tcpPacket = PacketHandler.AnalyseTCP(ipPacket);
                            if (tcpPacket.getPortDst() == 80 || tcpPacket.getPortSrc() == 80 || tcpPacket.getPortDst() == 8080 || tcpPacket.getPortSrc() == 8080) {
                                try {
                                    HTTPPacket httpPacket = PacketHandler.AnalyseHTTP(tcpPacket);
                                    t = httpPacket.getTimestampS() - time;
                                    ts = httpPacket.getTimestampMS() - timeM;
                                    System.out.println(n + " " + t + "." + ts + " " +httpPacket);
                                } catch (Exception e) {
                                    t = tcpPacket.getTimestampS() - time;
                                    ts = tcpPacket.getTimestampMS() - timeM;
                                    System.out.println(n + " " + t + "." + ts + " " +tcpPacket);
                                }

                            }
                            else {
                                t = tcpPacket.getTimestampS() - time;
                                ts = tcpPacket.getTimestampMS() - timeM;
                                System.out.println(n + " " + t + "." + ts + " " +tcpPacket);
                            }
                            break;
                            //TODO implement FTP
                        case 17 :
                            UDPPacket udpPacket = PacketHandler.AnalyseUDP(ipPacket);
                            if(udpPacket.getPortDst() == 53 || udpPacket.getPortSrc() == 53){
                                DNSPacket dnsPacket = PacketHandler.AnalyseDNS(udpPacket);
                                t = dnsPacket.getTimestampS() - time;
                                ts = dnsPacket.getTimestampMS() - timeM;
                                System.out.println(n + " " + t + "." + ts + " " +dnsPacket);
                            }
                            else if(udpPacket.getPortSrc() == 67 || udpPacket.getPortDst() == 67 || udpPacket.getPortSrc() == 68 || udpPacket.getPortDst() == 68){
                                DHCPPacket dhcpPacket = PacketHandler.AnalyseDHCP(udpPacket);
                                t = dhcpPacket.getTimestampS() - time;
                                ts = dhcpPacket.getTimestampMS() - timeM;
                                System.out.println(n + " " + t + "." + ts + " " +dhcpPacket);
                            }
                            //TODO implement QUIC
                            else {
                                t = udpPacket.getTimestampS() - time;
                                ts = udpPacket.getTimestampMS() - timeM;
                                System.out.println(n + " " + t + "." + ts + " " +udpPacket);
                            }
                            break;
                        default :
                            t = ipPacket.getTimestampS() - time;
                            ts = ipPacket.getTimestampMS() - timeM;
                            System.out.println(n + " " + t + "." + ts + " " +ipPacket);
                    }
                }
                else if (packet.etherType.equals("IPv6")) {
                    IPPacket ipPacket = PacketHandler.AnalyseIPv6(packet);
                    switch (ipPacket.getProtocol()){
                        case 1 :
                            ICMPPacket icmpPacket = PacketHandler.AnalyseICMP(ipPacket);
                            t = icmpPacket.getTimestampS() - time;
                            ts = icmpPacket.getTimestampMS() - timeM;
                            System.out.println(n + " " + t + "." + ts + " " +icmpPacket);
                            break;
                        case 6 :
                            TCPPacket tcpPacket = PacketHandler.AnalyseTCP(ipPacket);
                            if (tcpPacket.getPortDst() == 80 || tcpPacket.getPortSrc() == 80 || tcpPacket.getPortDst() == 8080 || tcpPacket.getPortSrc() == 8080) {
                                HTTPPacket httpPacket = PacketHandler.AnalyseHTTP(tcpPacket);
                                t = httpPacket.getTimestampS() - time;
                                ts = httpPacket.getTimestampMS() - timeM;
                                System.out.println(n + " " + t + "." + ts + " " +httpPacket);
                            }
                            else {
                                t = tcpPacket.getTimestampS() - time;
                                ts = tcpPacket.getTimestampMS() - timeM;
                                System.out.println(n + " " + t + "." + ts + " " +tcpPacket);
                            }
                            break;
                        //TODO implement FTP
                        case 17 :
                            UDPPacket udpPacket = PacketHandler.AnalyseUDP(ipPacket);
                            if(udpPacket.getPortDst() == 53 || udpPacket.getPortSrc() == 53){
                                DNSPacket dnsPacket = PacketHandler.AnalyseDNS(udpPacket);
                                t = dnsPacket.getTimestampS() - time;
                                ts = dnsPacket.getTimestampMS() - timeM;
                                System.out.println(n + " " + t + "." + ts + " " +dnsPacket);
                            }
                            else if(udpPacket.getPortSrc() == 67 || udpPacket.getPortDst() == 67 || udpPacket.getPortSrc() == 68 || udpPacket.getPortDst() == 68){
                                DHCPPacket dhcpPacket = PacketHandler.AnalyseDHCP(udpPacket);
                                t = dhcpPacket.getTimestampS() - time;
                                ts = dhcpPacket.getTimestampMS() - timeM;
                                System.out.println(n + " " + t + "." + ts + " " +dhcpPacket);
                            }
                            //TODO implement QUIC
                            else {
                                t = udpPacket.getTimestampS() - time;
                                ts = udpPacket.getTimestampMS() - timeM;
                                System.out.println(n + " " + t + "." + ts + " " +udpPacket);
                            }
                            break;
                        default :
                            t = ipPacket.getTimestampS() - time;
                            ts = ipPacket.getTimestampMS() - timeM;
                            System.out.println(n + " " + t + "." + ts + " " +ipPacket);
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
