package pcap.filters;

import pcap.Packet;

public class CounterFilter32 extends AbstractCounterFilter {
	
	public CounterFilter32(int counterPos) {
		super(counterPos);
	}
	
	@Override
	protected long getCounterValue(Packet packet) {
		byte[] data = packet.getAvailableData();
		return ((data[counterPos] & 0xff) << 24) | ((data[counterPos+1] & 0xff) << 16) | ((data[counterPos+2] & 0xff) << 8) | (data[counterPos+3] & 0xff);
	}
	
	@Override
	protected long getNextCounterValue(long currentCounterValue) {
		return (currentCounterValue + 1) & 0xffffffffl;
	}
	
	@Override
	protected long getNbPositionsLost(long currentPosition, long lastPosition) {
		return (((currentPosition - lastPosition) & 0xffffffffl) - 1) & 0xffffffffl;
	}
	
}
