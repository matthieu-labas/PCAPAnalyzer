package pcap.filters.impl;

import pcap.Packet;
import pcap.filters.AbstractMessageFilter;

public class Stat extends AbstractMessageFilter {
	
	public final static String DESCRIPTION = "Counts packet number, size and frequency";
	
	/** Timestamp of first received packet (ms). */
	protected long ms0;
	
	/** Timestamp of last received packet (ms). */
	protected long msLast;
	
	/** Total number of packets received. */
	protected int nbPackets;
	
	/** Total number of fragmented packets. */
	protected int nbFragmentsPackets;
	
	/** Total number of bytes received (total message length, not available message length). */
	protected long szTot;
	
	/** Minimum packet size. */
	protected long szMin;
	
	/** Maximum packet size. */
	protected long szMax;
	
	/** Number of watch. */
	protected int nWatch;
	
	public Stat() {
		szMin = szMax = -1;
		nWatch = 0;
	}
	
	@Override
	public void reset() {
		ms0 = msLast = 0l;
		nbPackets = 0;
		nbFragmentsPackets = 0;
		szMin = szMax = -1l;
		szTot = 0l;
	}
	
	@Override
	public String getDescription() {
		return DESCRIPTION;
	}
	
	public int getNbPackets() {
		return nbPackets;
	}
	
	@Override
	public boolean process(Packet packet) {
		long ts = packet.getPacketTimeMillis();
		int sz = packet.getTotalDataLength();
		if (nbPackets == 0) {
			ms0 = ts;
			szMin = szMax = sz;
		}
		msLast = ts;
		nbPackets++;
		if (packet.isFragmented())
			nbFragmentsPackets++;
		if (sz < szMin)
			szMin = sz;
		if (sz > szMax)
			szMax = sz;
		szTot += sz;
		return true;
	}

	@Override
	public void watch() {
		print(String.format("(watch %4d) - %s", ++nWatch, generateStats()));
	}
	
	public String generateStats() {
		double duration = (msLast - ms0) / 1000.0;
		if (nbPackets == 0)
			return "No packets received.";
		else
			return String.format("In %6.3f s: %6d packets, %4d fragmented (%6.3f%%%%), %8.3f packets/s, length: moy %6.1f min %4d max %4d, %4.3f kB/s",
					duration, nbPackets, nbFragmentsPackets, 100.0*nbFragmentsPackets/nbPackets, (double)nbPackets/duration, (double)szTot/nbPackets, szMin, szMax,
					szTot/(1024.0*duration));
	}

	@Override
	public boolean finish() {
		print(generateStats());
		return true;
	}

}
