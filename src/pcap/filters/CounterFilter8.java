package pcap.filters;

import pcap.Packet;

public class CounterFilter8 extends AbstractCounterFilter {
	
	public CounterFilter8(int counterPos) {
		super(counterPos);
	}
	
	@Override
	protected long getCounterValue(Packet packet) {
		return packet.getAvailableData()[counterPos] & 0xff;
	}
	
	@Override
	protected long getNextCounterValue(long currentCounterValue) {
		return (currentCounterValue + 1) & 0xff;
	}
	
	@Override
	protected long getNbPositionsLost(long currentPosition, long lastPosition) {
		return (((currentPosition - lastPosition) & 0xff) - 1) & 0xff;
	}
	
}
