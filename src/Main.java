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
            ArrayList<Packet> packetList = reader.openPcap("C:\\Users\\savpo\\Downloads\\dhcp.pcap");
            ArrayList<EtherPacket> etherlist = new ArrayList<EtherPacket>();
            for (Packet packet : packetList) {
                etherlist.add(PacketHandler.AnalyseEther(packet));
            }
            for (EtherPacket packet : etherlist) {
                if (packet.etherType.equals("ARP")) {
                    ARPPacket arpPacket = PacketHandler.AnalyseARP(packet);
                    System.out.println(arpPacket);
                }
                else if (packet.etherType.equals("IPv4")) {
                    IPPacket ipPacket = PacketHandler.AnalyseIPv4(packet);
                    switch (ipPacket.getProtocol()){
                        case 1 :
                            ICMPPacket icmpPacket = PacketHandler.AnalyseICMP(ipPacket);
                            System.out.println(icmpPacket);
                            break;
                        case 6 :
                            TCPPacket tcpPacket = PacketHandler.AnalyseTCP(ipPacket);
                            if (tcpPacket.getPortDst() == 80 || tcpPacket.getPortSrc() == 80 || tcpPacket.getPortDst() == 8080 || tcpPacket.getPortSrc() == 8080) {
                                HTTPPacket httpPacket = PacketHandler.AnalyseHTTP(tcpPacket);
                                System.out.println(httpPacket);
                            }
                            else {
                                System.out.println(tcpPacket);
                            }
                            break;
                            //TODO implement FTP
                        case 17 :
                            UDPPacket udpPacket = PacketHandler.AnalyseUDP(ipPacket);
                            if(udpPacket.getPortDst() == 53 || udpPacket.getPortSrc() == 53){
                                DNSPacket dnsPacket = PacketHandler.AnalyseDNS(udpPacket);
                                System.out.println(dnsPacket);
                            }
                            else if(udpPacket.getPortSrc() == 67 || udpPacket.getPortDst() == 67 || udpPacket.getPortSrc() == 68 || udpPacket.getPortDst() == 68){
                                DHCPPacket dhcpPacket = PacketHandler.AnalyseDHCP(udpPacket);
                                System.out.println(dhcpPacket);
                            }
                            //TODO implement QUIC
                            else {
                                System.out.println(udpPacket);
                            }
                            break;
                        default :
                            System.out.println(ipPacket);
                    }
                }
                else if (packet.etherType.equals("IPv6")) {
                    IPPacket ipPacket = PacketHandler.AnalyseIPv6(packet);
                    switch (ipPacket.getProtocol()){
                        case 1 :
                            ICMPPacket icmpPacket = PacketHandler.AnalyseICMP(ipPacket);
                            System.out.println(icmpPacket);
                            break;
                        case 6 :
                            TCPPacket tcpPacket = PacketHandler.AnalyseTCP(ipPacket);
                            if (tcpPacket.getPortDst() == 80 || tcpPacket.getPortSrc() == 80 || tcpPacket.getPortDst() == 8080 || tcpPacket.getPortSrc() == 8080) {
                                HTTPPacket httpPacket = PacketHandler.AnalyseHTTP(tcpPacket);
                                System.out.println(httpPacket);
                            }
                            else {
                                System.out.println(tcpPacket);
                            }
                            break;
                        //TODO implement FTP
                        case 17 :
                            UDPPacket udpPacket = PacketHandler.AnalyseUDP(ipPacket);
                            if(udpPacket.getPortDst() == 53 || udpPacket.getPortSrc() == 53){
                                DNSPacket dnsPacket = PacketHandler.AnalyseDNS(udpPacket);
                                System.out.println(dnsPacket);
                            }
                            else if(udpPacket.getPortSrc() == 67 || udpPacket.getPortDst() == 67 || udpPacket.getPortSrc() == 68 || udpPacket.getPortDst() == 68){
                                DHCPPacket dhcpPacket = PacketHandler.AnalyseDHCP(udpPacket);
                                System.out.println(dhcpPacket);
                            }
                            //TODO implement QUIC
                            else {
                                System.out.println(udpPacket);
                            }
                            break;
                        default :
                            System.out.println(ipPacket);
                    }
                }
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }

    }

}
