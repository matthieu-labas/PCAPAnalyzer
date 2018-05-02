package pcap;

import java.net.InetAddress;
import java.util.Date;

import pcap.NetworkFrame.EthernetFrame;
import pcap.NetworkFrame.IPv4Frame;
import pcap.NetworkFrame.TCPFrame;
import pcap.NetworkFrame.UDPFrame;
import pcap.PCAPReader.PCAPPacketHeader;

public class Packet {
	
	private PCAPPacketHeader pcapHeader;
	private EthernetFrame ethernetFrame;
	private IPv4Frame ip4;
	private TCPFrame tcpFrame;
	private UDPFrame udpFrame;
	private int totalDatalen;
	private byte[] data;
	
	/** Packet number in the stream. If packet is fragmented, it is the number of the first fragment. */
	private int packetNum;
	
	/** Total number of fragments for the packet (minimum is 1 fragment). */
	private int nbFragments;
	
	/**
	 * {@code true} when packet is fragmented and more fragments are expected (i.e. no merge done
	 * with unfragmented packet).
	 */
	private boolean moreFragments;
	
	/** Public field that can be used by Filters to store a counter. */
	public long counter;
	
	public Packet(PCAPPacketHeader pcapPacket, EthernetFrame ethernetFrame,
			IPv4Frame ip4, TCPFrame tcpFrame, UDPFrame udpFrame, int packetNum,
			byte[] data, int totalDatalen) {
		
		this.pcapHeader = pcapPacket;
		this.ethernetFrame = ethernetFrame;
		this.ip4 = ip4;
		this.tcpFrame = tcpFrame;
		this.udpFrame = udpFrame;
		this.packetNum = packetNum;
		this.data = data;
		this.totalDatalen = totalDatalen;
		nbFragments = 1;
		moreFragments = ip4.isFragmented();
	}
	
	public Packet(Packet o, byte[] data) {
		this(o.pcapHeader, o.ethernetFrame, o.ip4, o.tcpFrame, o.udpFrame, o.packetNum, data, data.length);
	}
	
	/**
	 * @return {@code true} if packet is fragmented ('fragmentation' bit set in IP header).
	 */
	public boolean isFragmented() {
		return ip4.isFragmented();
	}
	
	/**
	 * @return {@code true} if packet is a fragment ('fragment offset' > 0 in IP header).
	 */
	public boolean isFragment() {
		return ip4.isFragment();
	}
	
	/**
	 * @return {@code true} if more fragments are expected for this packet.
	 */
	public boolean expectMoreFragments() {
		return moreFragments;
	}
	
	/**
	 * Checks if a packet is a fragment of this packet, but not necessarily the next one.
	 * @param nextFragment A potential next fragment packet.
	 * @return {@code true} if the packet is a next fragment of this packet.
	 */
	public boolean testFragment(Packet nextFragment) {
		return ip4.isFragmented() && ip4.ident == nextFragment.ip4.ident; // && nextFragment.ip4.fragOffset != totalDatalen + 8
	}
	
	/**
	 * Merge this fragmented packet with the next one. Total data length is updated.
	 * @param nextFragment The next packet, that should be the next fragment of the current packet.
	 * @return {@code false} if packets could not be merged together (i.e. this packet is not
	 *         fragmented, IPv4 IDs are not equal).
	 */
	public boolean mergeWith(Packet nextFragment) {
		if (!testFragment(nextFragment))
			return false;
		nbFragments++;
		totalDatalen += nextFragment.totalDatalen;
		moreFragments = nextFragment.isFragmented();
		return true;
	}
	
	public PCAPPacketHeader getPCAPPacketHeader() {
		return pcapHeader;
	}
	
	public int getPacketNumber() {
		return packetNum;
	}
	
	public int getNbFragments() {
		return nbFragments;
	}
	
	public long getPacketTimeMillis() {
		if (pcapHeader == null)
			return -1;
		return Math.round(pcapHeader.ts_sec * 1000.0 + pcapHeader.ts_usec * .001);
	}
	
	public Date getPacketDate() {
		return new Date(getPacketTimeMillis());
	}
	
	public byte[] getSourceMAC() {
		return ethernetFrame.srcMAC;
	}
	
	public byte[] getDestinationMAC() {
		return ethernetFrame.dstMAC;
	}
	
	public int getIPID() {
		return ip4.ident;
	}
	
	public InetAddress getSourceIP() {
		return ip4.srcIP;
	}
	
	public InetAddress getDestinationIP() {
		return ip4.dstIP;
	}
	
	public int getProtocol() {
		if (udpFrame != null)
			return NetworkFrame.PROTOCOL_UDP;
		
		if (tcpFrame != null)
			return NetworkFrame.PROTOCOL_TCP;
		
		return 0;
	}
	
	public int getSourcePort() {
		if (udpFrame != null)
			return udpFrame.srcPort;
		
		if (tcpFrame != null)
			return tcpFrame.src_port;
		
		return 0;
	}
	
	public int getDestinationPort() {
		if (udpFrame != null)
			return udpFrame.dstPort;
		
		if (tcpFrame != null)
			return tcpFrame.dstPort;
		
		return 0;
	}
	
	public byte[] getAvailableData() {
		return data;
	}
	
	public int getAvailableDataLength() {
		return data.length;
	}
	
	public int getTotalDataLength() {
		return totalDatalen;
	}
	
	@Override
	public String toString() {
		return String.format("#%d/%d: %s:%d > %s:%d (%d bytes)",
				packetNum, counter, getSourceIP().getHostAddress(), getSourcePort(),
				getDestinationIP().getHostAddress(), getDestinationPort(), getTotalDataLength());
	}
}
