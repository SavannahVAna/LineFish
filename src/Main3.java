import java.io.FileNotFoundException;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class Main3 {
    public static void main(String[] args) {
        PcapReader reader = new PcapReader();

        try {
            double t;
            long ti;
            int n = 0;
            String filename;
            if(args.length == 0){
                filename = "C:\\Users\\savpo\\Downloads\\quic.pcap"; //for debugging purposes
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
                            if ( PacketHandler.testHTTP(tcpPacket)) {
                                try {
                                    HTTPPacket httpPacket = PacketHandler.AnalyseHTTP(tcpPacket);

                                    System.out.println(n + " " + t  + " " +httpPacket);
                                } catch (Exception e) {


                                    System.out.println(n + " " + t + " " +tcpPacket);
                                }

                            }
                            else if( PacketHandler.isFTP(tcpPacket)){//TODO regarder plus en détails des fois ça marche pas
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
                            if( PacketHandler.isDNS(udpPacket)){
                                DNSPacket dnsPacket = PacketHandler.AnalyseDNS(udpPacket);


                                System.out.println(n + " " + t +  " " +dnsPacket);
                            }
                            else if(PacketHandler.isDHCP(udpPacket)){
                                DHCPPacket dhcpPacket = PacketHandler.AnalyseDHCP(udpPacket);


                                System.out.println(n + " " + t  + " " +dhcpPacket);
                            }
                            else if (PacketHandler.isQUICS(udpPacket)) {
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
                            if ( PacketHandler.testHTTP(tcpPacket)) {
                                HTTPPacket httpPacket = PacketHandler.AnalyseHTTP(tcpPacket);


                                System.out.println(n + " " + t  + " " +httpPacket);
                            }
                            else if( PacketHandler.isFTP(tcpPacket)){
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
                            if(PacketHandler.isDNS(udpPacket)){
                                DNSPacket dnsPacket = PacketHandler.AnalyseDNS(udpPacket);

                                System.out.println(n + " " + t  + " " +dnsPacket);
                            }
                            else if(PacketHandler.isDHCP(udpPacket)){
                                DHCPPacket dhcpPacket = PacketHandler.AnalyseDHCP(udpPacket);

                                System.out.println(n + " " + t  + " " +dhcpPacket);
                            } else if (PacketHandler.isQUICS(udpPacket)) {
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
