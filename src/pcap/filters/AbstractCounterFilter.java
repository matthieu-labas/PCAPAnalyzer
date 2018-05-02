package pcap.filters;

import java.util.Iterator;
import java.util.LinkedList;

import pcap.PCAPAnalyzer;
import pcap.Packet;
import pcap.filters.impl.Stat;

/**
 * Filter able to retrieve a counter from a Packet and count packet losses.
 * 
 * @author Matthieu Labas
 */
public abstract class AbstractCounterFilter extends Stat {
	
	/** Counter position in data stream got from {@link Packet#getAvailableData()}. */
	protected int counterPos;
	
	/** Maximum counter value. */
	protected long maxCounterValue;
	
	/**
	 * Number of "lost" packet above which we consider that it is not a loss but an ordering
	 * problem.<br/>
	 * It is defined as 90% of the maximum Counter value (i.e. 230 for 8-bits counters, 58982 for
	 * 16-bits counters).
	 */
	protected long reorderThreshold;
	
	/** Last known counter value from processed packets. */
	protected long lastCounterValue;
	
	/** Number of lost packets. */
	protected long nbPacketsLost;
	
	/** Maximum number of packet lost in a row. */
	protected long nbPacketsLostMax;
	
	/** Number of duplicated packets. */
	protected int nbPacketsDuplicated;
	
	/** Number of reordered packets. */
	protected int nbPacketsUnordered;
	
	/** Maximum number of position to correct order. */
	protected int nbPacketsUnorderedMax;
	
	/** FIFO of last received packets, to check for reordering and duplication. */
	protected LinkedList<Packet> packetsFIFO;
	
	/** Number of packets to keep in reordering FIFO. */
	protected int szReorder;
	
	public AbstractCounterFilter(int counterPos, int szReorder) {
		super();
		this.counterPos = counterPos;
		this.szReorder = szReorder;
		packetsFIFO = new LinkedList<Packet>();
		maxCounterValue = getNbPositionsLost(-1, 0);
		reorderThreshold = maxCounterValue - maxCounterValue / 10;
	}
	
	public AbstractCounterFilter(int counterPos) {
		this(counterPos, PCAPAnalyzer.DEFAULT_REORDUPL_WINDOW);
	}
	
	@Override
	public void reset() {
		super.reset();
		lastCounterValue = 0;
		nbPacketsLost = nbPacketsLostMax = 0;
		nbPacketsUnordered = nbPacketsUnorderedMax = 0;
		nbPacketsDuplicated = 0;
	}
	
	protected abstract long getCounterValue(Packet packet);
	
	protected abstract long getNextCounterValue(long lastCounterValue);
	
	protected abstract long getNbPositionsLost(long counter, long counter2);
	
	@Override
	public boolean process(Packet packet) {
		long counter = getCounterValue(packet);
		packet.counter = counter;
		
		Iterator<Packet> iter;
		Packet p;
		
		// Search the previous packets for possible duplicates
		for (iter = packetsFIFO.iterator(); iter.hasNext();) {
			p = iter.next();
			if (p.counter == counter) { // Duplicated packet is discarded
				nbPacketsDuplicated++;
				printVerbose("#%d duplicate of #%d (counter %d)", packet.getPacketNumber(), p.getPacketNumber(), counter);
				return true;
			}
		}
		
		// Search the previous packets for possible duplicates
		int iInsert = -1;
		iter = packetsFIFO.descendingIterator();
		if (iter.hasNext()) { // If we don't detect reordering on the last packet, there is no point in checking for earlier packets
			p = iter.next();
			if (getNbPositionsLost(counter, p.counter) >= reorderThreshold) { // More than 'reorderThreshold' packets lost: probable reordering
				nbPacketsUnordered++;
				iInsert = packetsFIFO.size() - 1;
				while (iter.hasNext() && iter.next().counter > counter) // Search for the appropriate insertion
					iInsert--;
				int npos = packetsFIFO.size() - iInsert + 1;
				if (npos > nbPacketsUnorderedMax)
					nbPacketsUnorderedMax = npos;
				printVerbose("#%d reordered by %d positions", packet.getPacketNumber(), npos);
			}
		}
		if (iInsert >= 0)
			packetsFIFO.add(iInsert, packet);
		else
			packetsFIFO.offer(packet);
		
		if (packetsFIFO.size() < szReorder)
			return true;
		
		return processPacketFIFO(packetsFIFO.pop());
	}
	
	protected boolean processPacketFIFO(Packet packet) {
		if (!super.process(packet))
			return false;
		
		long counter = packet.counter;
		if (nbPackets > 1) {
			long next = getNextCounterValue(lastCounterValue);
			if (counter != next) {
				long nLost = getNbPositionsLost(counter, lastCounterValue);
				if (nLost > nbPacketsLostMax)
					nbPacketsLostMax = nLost;
				nbPacketsLost += nLost;
				printVerbose("#%d: %d packets lost (jump %d > %d)", packet.getPacketNumber(),
						nLost, lastCounterValue, counter);
			}
		}
		lastCounterValue = packet.counter;
		
		return true;
	}
	
	@Override
	public String generateStats() {
		double duration = (msLast - ms0) / 1000.0;
		long nbPacketsTot = nbPackets + nbPacketsLost;
		if (nbPacketsTot == 0)
			return super.generateStats();
		else
			return String.format("In %6.3f s: %5d packets, %3d duplicated (%6.3f%%%%), %3d unordered (%6.3f%%%%, %2d max positions), %4d lost (%6.3f%%%%, %2d max in a row), %4d fragmented (%6.3f%%%%), %8.3f packets/s, length: moy %6.1f min %4d max %4d, %6.3f kB/s",
					duration, nbPacketsTot, nbPacketsDuplicated, 100.0*nbPacketsDuplicated/nbPackets,
					nbPacketsUnordered, 100.0*nbPacketsUnordered/nbPackets, nbPacketsUnorderedMax,
					nbPacketsLost, 100.0*nbPacketsLost/nbPacketsTot, nbPacketsLostMax,
					nbFragmentsPackets, 100.0*nbFragmentsPackets/nbPacketsTot, (double)nbPacketsTot/duration,
					(double)szTot/nbPacketsTot, szMin, szMax, szTot/(1024.0*duration));
	}
	
	@Override
	public boolean finish() {
		// Empty packet FIFO
		for (Packet packet = packetsFIFO.pop(); packet != null; packet = packetsFIFO.poll())
			processPacketFIFO(packet);
		return super.finish();
	}

}
