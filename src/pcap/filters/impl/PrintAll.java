package pcap.filters.impl;

import pcap.Packet;
import pcap.filters.AbstractMessageFilter;

/**
 * Print every packet received.
 * 
 * @author Matthieu Labas
 */
public class PrintAll extends AbstractMessageFilter {

	public final static String DESCRIPTION = "Prints every packet received";
	
	@Override
	public String getDescription() {
		return DESCRIPTION;
	}
	
	@Override
	public boolean process(Packet packet) {
		print(packet.toString());
		return true;
	}

	@Override
	public void watch() {
	}

	@Override
	public boolean finish() {
		return true;
	}

}
