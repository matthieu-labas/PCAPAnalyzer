package pcap.filters.impl;

import java.net.InetAddress;
import java.util.Comparator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import pcap.Packet;

public class StatDest extends Stat {
	
	public final static String DESCRIPTION = "Listing statistics on packets Destination IP";
	
	protected Map<InetAddress,Stat> statsIP;
	
	public StatDest() {
		super();
		statsIP = new TreeMap<InetAddress,Stat>(new Comparator<InetAddress>() {
			@Override
			public int compare(InetAddress o1, InetAddress o2) {
				byte[] adr1 = o1.getAddress();
				byte[] adr2 = o2.getAddress();
				if (adr1.length < adr2.length)
					return -1;
				if (adr1.length > adr2.length)
					return 1;
				for (int i = 0; i < adr1.length; i++) {
					if (adr1[i] == adr2[i])
						continue;
					return adr1[i] < adr2[i] ? -1 : 1;
				}
				return 0;
			}
		});
	}
	
	@Override
	public boolean process(Packet packet) {
		if (!super.process(packet))
			return false;
		
		InetAddress ip = packet.getDestinationIP();
		Stat filter = statsIP.get(ip);
		if (filter == null) {
			filter = new Stat();
			statsIP.put(ip, filter);
		}
		
		return filter.process(packet);
	}
	
	@Override
	public void reset() {
		super.reset();
		statsIP.clear();
	}
	
	@Override
	public String generateStats() {
		String stats = super.generateStats();
		for (Entry<InetAddress,Stat> e : statsIP.entrySet())
			stats += String.format("\n--%15s: %s", e.getKey().getHostAddress(), e.getValue().generateStats());
		return stats;
	}
}
