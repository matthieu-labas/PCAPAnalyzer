package test;

import pcap.Packet;
import pcap.filters.CounterFilter16;
import pcap.filters.FilterPrinter;
import pcap.filters.MessageFilter;

public class TestFilterFIFO {

	public static void main(String[] args) {
		CounterFilter16 flt = new CounterFilter16(0);
		byte[] data;
		Packet p;
		int noPacket = 1;
		FilterPrinter printer = new FilterPrinter() {
			@Override
			public void filterPrint(MessageFilter filter, String format, Object... args) {
				System.out.println(String.format(format.replace("%", "%%"), args));
			}
			
			@Override
			public void setFilterVerbose(boolean verbose) {
			}
			
			@Override
			public void filterPrintVerbose(MessageFilter filter, String format, Object... args) {
				filterPrint(filter, format, args);
			}
		};
		flt.setPrinter(printer);
		
		data = new byte[]{ (byte)0xff, (byte)0x00 };
		p = new Packet(null, null, null, null, null, noPacket++, data, 0);
		flt.process(p);
		data = new byte[]{ (byte)0x00, (byte)0xff };
		p = new Packet(null, null, null, null, null, noPacket++, data, 0);
		flt.process(p);
		data = new byte[]{ (byte)0x01, (byte)0x00 };
		p = new Packet(null, null, null, null, null, noPacket++, data, 0);
		flt.process(p);
		data = new byte[]{ (byte)0x01, (byte)0x05 };
		p = new Packet(null, null, null, null, null, noPacket++, data, 0);
		flt.process(p);
		data = new byte[]{ (byte)0x01, (byte)0x06 };
		p = new Packet(null, null, null, null, null, noPacket++, data, 0);
		flt.process(p);
		data = new byte[]{ (byte)0x01, (byte)0x08 };
		p = new Packet(null, null, null, null, null, noPacket++, data, 0);
		flt.process(p);
		data = new byte[]{ (byte)0x01, (byte)0x07 };
		p = new Packet(null, null, null, null, null, noPacket++, data, 0);
		flt.process(p);
		data = new byte[]{ (byte)0x01, (byte)0x0a };
		p = new Packet(null, null, null, null, null, noPacket++, data, 0);
		flt.process(p);
		data = new byte[]{ (byte)0x01, (byte)0x07 };
		p = new Packet(null, null, null, null, null, noPacket++, data, 0);
		flt.process(p);
		data = new byte[]{ (byte)0x01, (byte)0x08 };
		p = new Packet(null, null, null, null, null, noPacket++, data, 0);
		flt.process(p);
		
		flt.finish();
	}

}
