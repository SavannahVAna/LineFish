import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

public class Options {
    static void TCPStream(ArrayList<Packet> p, int n) throws UnknownHostException {
        Packet fistpacket = p.get(n);
        //long t;

        //int nb = 0;
        EtherPacket firstEtherPacket = PacketHandler.AnalyseEther(fistpacket);
        IPPacket firstIPpacket = PacketHandler.AnalyseIPv4(firstEtherPacket);
        TCPPacket firstTCPPacket = PacketHandler.AnalyseTCP(firstIPpacket);
        ArrayList<TCPPacket> tcp = new ArrayList<TCPPacket>();

        ArrayList<EtherPacket> etherlist = new ArrayList<EtherPacket>();

        for (Packet packet : p) {
            etherlist.add(PacketHandler.AnalyseEther(packet));
        }

        for (EtherPacket packet : etherlist) {

            if (packet.etherType.equals("IPv4")) {
                IPPacket ipPacket = PacketHandler.AnalyseIPv4(packet);
                if (ipPacket.getProtocol() == 6) {
                    TCPPacket tcpPacket = PacketHandler.AnalyseTCP(ipPacket);
                    if (tcpPacket.getPortDst() == 80 || tcpPacket.getPortSrc() == 80 || tcpPacket.getPortDst() == 8080 || tcpPacket.getPortSrc() == 8080) {
                        try {
                            HTTPPacket httpPacket = PacketHandler.AnalyseHTTP(tcpPacket);
                            tcp.add(httpPacket);
                        } catch (Exception e) {
                            //t = tcpPacket.getTimestampS() ;
                            tcp.add(tcpPacket);
                        }

                    } else {
                        tcp.add(tcpPacket);
                    }

                }
            }
            else if (packet.etherType.equals("IPv6")) {
                IPPacket ipPacket = PacketHandler.AnalyseIPv6(packet);
                if (ipPacket.getProtocol() == 6) {
                    TCPPacket tcpPacket = PacketHandler.AnalyseTCP(ipPacket);
                    if (tcpPacket.getPortDst() == 80 || tcpPacket.getPortSrc() == 80 || tcpPacket.getPortDst() == 8080 || tcpPacket.getPortSrc() == 8080) {
                        try {
                            HTTPPacket httpPacket = PacketHandler.AnalyseHTTP(tcpPacket);
                            tcp.add(httpPacket);
                        } catch (Exception e) {
                            tcp.add(tcpPacket);
                        }

                    } else {
                        tcp.add(tcpPacket);
                    }

                }
            }

        }
        int split = 0;
        /*for(int i = 0; i<tcp.size(); i++) {
            TCPPacket packet = tcp.get(i);
            //si le packet a le meme sequence number et ack number que le paquet recherché on peut considéerer que c'est lui
            if(packet.getSeqNb() == firstTCPPacket.getSeqNb() && packet.getAckNb() == firstTCPPacket.getAckNb()) {
                split = i;
            }
        }*/
        //ArrayList<TCPPacket> debut = new ArrayList<>(tcp.subList(0, split));
        //ArrayList<TCPPacket> fin = new ArrayList<>(tcp.subList(split +1,tcp.size()));
        int seq = firstTCPPacket.getSeqNb();
        int ack = firstTCPPacket.getAckNb();
        int prtsrc = firstTCPPacket.getPortSrc();
        int prtdst = firstTCPPacket.getPortDst();
        ArrayList<TCPPacket> realList= new ArrayList<>();
        for (TCPPacket packet : tcp) {
            if ((packet.getPortSrc() == prtsrc || packet.getPortDst() == prtsrc) &&
                    (packet.getPortSrc() == prtdst || packet.getPortDst() == prtdst)) {
                realList.add(packet);
            }
        }
        /*for (int i = debut.size() -1; i>=0; i--) {
            TCPPacket packet = debut.get(i);
            if (packet.getPortDst() == prtsrc && packet.getPortSrc() == prtdst && packet.getAckNb() == seq && packet.getSeqNb() == ack-1) {
                realList.add(packet);
                prtsrc = firstTCPPacket.getPortDst();
                prtdst = firstTCPPacket.getPortSrc();
                seq --;
                ack --;
            }
        }
        seq = firstTCPPacket.getSeqNb();
        ack = firstTCPPacket.getAckNb();
        Collections.reverse(realList);
        for (TCPPacket packet : fin) {
            if (packet.getSeqNb() == ack && packet.getAckNb() == seq+1 && packet.getPortDst() == prtsrc && packet.getPortSrc() == prtdst) {
                realList.add(packet);
                prtsrc = firstTCPPacket.getPortDst();
                prtdst = firstTCPPacket.getPortSrc();
                seq++;
                ack++;
            }
        }*/
        ArrayList<TCPPacket> secondList= new ArrayList<>(); //1 chercher antécédents
        boolean update = false;
        do{
            update = false;
            for (TCPPacket packet : realList) {
                if (packet.getAckNb() == seq && packet.getSeqNb() == ack - 1) {
                    if (!secondList.contains(packet)) {
                        secondList.add(packet);
                        seq = packet.getSeqNb();
                        ack = packet.getAckNb();
                        update = true;
                    }
                }
            }
        }while(update);
        Collections.reverse(secondList);
        secondList.add(firstTCPPacket);
        seq = firstTCPPacket.getSeqNb();
        ack = firstTCPPacket.getAckNb();

        do{
            update = false;
            for (TCPPacket packet : realList) {
                if(packet.getAckNb()== seq +1 && packet.getSeqNb() == ack){
                    if (!secondList.contains(packet)) {
                    secondList.add(packet);
                    seq = packet.getSeqNb();
                    ack = packet.getAckNb();
                    update = true;
                    }
                }
            }
        }while(update);


        //long time = etherlist.getFirst().getTimestampS();
        //double ti;
        for (TCPPacket packet : realList) {
            //t = packet.getTimestampS() - time;
            //ti = t/1000000.0;
            //System.out.println(nb + " " + ti  +" " + packet.getMessage());
            System.out.println(packet.getMessage());
        }
    }
}
