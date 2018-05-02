package pcap.filters.impl;

import pcap.Packet;
import pcap.filters.AbstractMessageFilter;

/**
 * The Empty Filter. Merely here to show minimum Filter implementation.
 *  
 * @author Matthieu Labas
 */
public class Empty extends AbstractMessageFilter {
	
	public final static String DESCRIPTION = "Silently processes packets";
	
	@Override
	public String getDescription() {
		return DESCRIPTION;
	}

	@Override
	public boolean process(Packet packet) {
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
