package pcap.filters.impl;

import pcap.Packet;
import pcap.filters.CounterFilter16;

public class RTP extends CounterFilter16 {

	public final static String DESCRIPTION = "Analysis of RTP streams";
	
	public RTP() {
		super(2);
	}
	
	@Override
	public void watch() {
		print(String.format("(watch %d) - %s", ++nWatch, generateStats()));
	}
	
	@Override
	public boolean process(Packet packet) {
		if (packet.getSourcePort() % 2 != 0) // RTP is always on even ports
			return false;
		
		return super.process(packet);
	}
}
