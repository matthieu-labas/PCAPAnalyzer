package pcap.filters;

import pcap.Packet;

public class CounterFilter16 extends AbstractCounterFilter {
	
	public CounterFilter16(int counterPos) {
		super(counterPos);
	}
	
	@Override
	protected long getCounterValue(Packet packet) {
		byte[] data = packet.getAvailableData();
		return (data[counterPos] & 0xff) << 8 | (data[counterPos+1] & 0xff);
	}
	
	@Override
	protected long getNextCounterValue(long currentCounterValue) {
		return (currentCounterValue + 1) & 0xffff;
	}
	
	@Override
	protected long getNbPositionsLost(long currentPosition, long lastPosition) {
		return (((currentPosition - lastPosition) & 0xffff) - 1) & 0xffff;
	}
	
}
