package pcap;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;

import pcap.filters.MessageFilter;

public class Selector {
	
	private static InetAddress INADDR_ANY;
	
	static {
		try {
			INADDR_ANY = InetAddress.getByAddress(new byte[]{0, 0, 0, 0});
		} catch (UnknownHostException e) { }
	}
	
	private InetAddress srcAddress;
	private int srcPort;
	private InetAddress dstAddress;
	private int dstPort;
	private int protocol;
	
	/**List of active Filters for the Selector.*/
	private List<MessageFilter> filters;
	
	/**Additional Filters to handle watch events.*/
	private List<MessageFilter> watchFilters;
	
	public Selector() {
		filters = new LinkedList<MessageFilter>();
	}
	
	/**
	 * @param descr {@code "[<TCP|UDP>$][<source IP>|any][:<source port>]=[<dest IP>|any][:<dest port>]"}
	 */
	public Selector(String descr) {
		this();
		int ich = descr.indexOf('$');
		if (ich >= 0) {
			String prot = descr.substring(0, ich);
			descr = descr.substring(ich+1);
			if (prot.equalsIgnoreCase("TCP"))
				protocol = NetworkFrame.PROTOCOL_TCP;
			else if (prot.equalsIgnoreCase("UDP"))
				protocol = NetworkFrame.PROTOCOL_UDP;
			else if (prot.equalsIgnoreCase("IGMP"))
				protocol = NetworkFrame.PROTOCOL_IGMP;
			else
				System.err.println(String.format("Unknown protocol '%s'. Ignored.", prot));
		}
		
		String[] parts = descr.substring(ich+1).split("="); // 0 if ich is -1, or next character otherwise
		InetSocketAddress addr = parseAddress(parts[0]);
		srcAddress = addr.getAddress();
		srcPort = addr.getPort();
		if (parts.length == 1) { // Same info for both source and destination
			dstAddress = srcAddress;
			dstPort = srcPort;
		} else {
			addr = parseAddress(parts[1]);
			dstAddress = addr.getAddress();
			dstPort = addr.getPort();
		}
	}

	private InetSocketAddress parseAddress(String ipPort) {
		InetAddress addr;
		int port;
		String ip;
		String[] parts = ipPort.split(":");
		if (parts.length == 2) { // Source port
			try {
				port = Integer.valueOf(parts[1]);
			} catch (NumberFormatException e) {
				System.err.println(String.format("Invalid port '%s'. Ignored.", parts[1]));
				port = 0;
			}
			ip = parts[0];
		} else {
			port = 0;
			ip = parts[0];
		}
		try {
			if (ip.isEmpty() || ip.equalsIgnoreCase("ANY"))
				addr = INADDR_ANY;
			else
				addr = InetAddress.getByName(ip);
		} catch (UnknownHostException e) {
			System.err.println(String.format("Invalid address '%s'. Ignored.", ip));
			addr = INADDR_ANY;
		}
		
		return new InetSocketAddress(addr, port);
	}
	
	public void addFilter(MessageFilter filter) {
		filters.add(filter);
	}
	
	public void enableWatch() {
		watchFilters = new LinkedList<MessageFilter>();
		for (MessageFilter filter : filters) {
			watchFilters.add(filter.duplicate());
		}
	}
	
	public boolean acceptsPacket(Packet packet) {
		// Check protocol
		if (protocol != 0 && packet.getProtocol() != protocol)
			return false;
		
		// Check IP
		if (srcAddress == dstAddress) { // Selector source == destination => packet source or destination IP should match
			if (!srcAddress.equals(INADDR_ANY) && !srcAddress.equals(packet.getSourceIP()) && !srcAddress.equals(packet.getDestinationIP()))
				return false;
		} else {
			if (!srcAddress.equals(INADDR_ANY) && !srcAddress.equals(packet.getSourceIP()))
				return false;
			if (!dstAddress.equals(INADDR_ANY) && !dstAddress.equals(packet.getDestinationIP()))
				return false;
		}
		
		// Check port
		if (srcPort == dstPort) {
			if (srcPort > 0 && packet.getSourcePort() != srcPort && packet.getDestinationPort() != srcPort)
				return false;
		} else {
			if (srcPort > 0 && packet.getSourcePort() != srcPort)
				return false;
			if (dstPort > 0 && packet.getDestinationPort() != dstPort)
				return false;
		}
		
		return true;
	}
	
	/**
	 * Sends the packet to all Filters and returns the number of Filters which were able to process
	 * it.
	 * @param packet The packet to send through the Filters.
	 * @return The number of Filters which understood the packet.
	 */
	public int process(Packet packet) {
		int nFiltersOK = 0;
		for (MessageFilter filter : filters)
			if (filter.process(packet))
				nFiltersOK++;
		
		// Send the packet to Watch Filters
		if (watchFilters != null) {
			for (MessageFilter filter : watchFilters)
				filter.process(packet);
		}
		
		return nFiltersOK;
	}
	
	/**
	 * Calls the {@link MessageFilter#watch()} on all Watch Filters and
	 * {@link MessageFilter#reset()} them.
	 */
	public void watch() {
		if (watchFilters != null) {
			for (MessageFilter filter : watchFilters) {
				filter.watch();
				filter.reset();
			}
		}
	}
	
	/**
	 * Call {@link MessageFilter#finish()} on all Filters.
	 * @return The number of Filters which finished correctly.
	 */
	public int finish() {
		int nFiltersOK = 0;
		for (MessageFilter filter : filters)
			if (filter.finish())
				nFiltersOK++;
		return nFiltersOK;
	}
	
}
