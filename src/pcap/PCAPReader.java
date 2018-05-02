package pcap;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import pcap.NetworkFrame.EthernetFrame;
import pcap.NetworkFrame.IPv4Frame;
import pcap.NetworkFrame.TCPFrame;
import pcap.NetworkFrame.UDPFrame;

public class PCAPReader {

	public static final int LINKTYPE_ETHERNET = 1;
	
	public static int readUINT8(InputStream is) throws IOException, EOFException {
		int b = is.read();
		if (b < 0)
			throw new EOFException();
		return b & 0xff;
	}
	
	public static int readUINT8(ByteBuffer buf) {
		return buf.get() & 0xff;
	}
	
	public static int readUINT16_BE(InputStream is) throws IOException, EOFException {
		byte[] data = new byte[2];
		if (is.read(data) < 0)
			throw new EOFException();
		return (data[0]&0xff) << 8 | (data[1]&0xff);
	}
	
	public static int readUINT16(ByteBuffer buf) {
		return buf.getShort() & 0xffff;
	}
	
	public static int readUINT16_LE(InputStream is) throws IOException, EOFException {
		byte[] data = new byte[2];
		if (is.read(data) < 0)
			throw new EOFException();
		return (data[1]&0xff) << 8 | (data[0]&0xff);
	}
	
	public static int readUINT32_BE(InputStream is) throws IOException, EOFException {
		byte[] data = new byte[4];
		if (is.read(data) < 0)
			throw new EOFException();
		return (data[0]&0xff) << 24 | (data[1]&0xff) << 16 | (data[2]&0xff) << 8 | (data[3]&0xff);
	}
	
	public static int readUINT32(ByteBuffer buf) {
		return buf.getInt() & 0xffffffff;
	}
	
	public static int readUINT32_LE(InputStream is) throws IOException, EOFException {
		byte[] data = new byte[4];
		if (is.read(data) < 0)
			throw new EOFException();
		return (data[3]&0xff) << 24 | (data[2]&0xff) << 16 | (data[1]&0xff) << 8 | (data[0]&0xff);
	}
	
	
	public static class PCAPHeader {
		public static final int PCAP_MAGIC = 0xa1b2c3d4;
		
		public byte[] header;
		public int magicNumber;
		public int versionMajor;
		public int versionMinor;
		public int thiszone;
		public int sigfigs;
		public int snaplen;
		public int network; /* One of LINKTYPE_* */
		
		public PCAPHeader(InputStream is) throws IOException {
			header = new byte[24];
			try {
				if (is.read(header) < 0)
					throw new EOFException();
			} catch (IOException e) {
				throw new IOException(e.getMessage());
			}
			ByteBuffer buf = ByteBuffer.wrap(header);
			buf.order(ByteOrder.LITTLE_ENDIAN); // Little Endian for PCAP Header
			try {
				magicNumber = readUINT32(buf);
				if (magicNumber != PCAP_MAGIC)
					throw new IOException(String.format("Wrong PCAP Magic number '%08x' (should be '%08x')!", magicNumber, PCAP_MAGIC));
				versionMajor = readUINT16(buf);
				versionMinor = readUINT16(buf);
				thiszone = readUINT32(buf);
				sigfigs = readUINT32(buf);
				snaplen = readUINT32(buf);
				network = readUINT32(buf);
				if (network != LINKTYPE_ETHERNET)
					throw new IOException(String.format("Wrong Link type '%d' (should be '%d')!", network, LINKTYPE_ETHERNET));
			} catch (BufferUnderflowException e) {
				throw new IOException(e.getMessage());
			}
			buf = null;
		}
		
		public byte[] getHeader() {
			return header;
		}
	}
	
	
	public static class PCAPPacketHeader {
		byte[] header;
		public int ts_sec;
		public int ts_usec;
		public int includedLength;
		public int originalLength;
		
		/**
		 * The packet number in the stream.
		 */
		public int packetNum;
		
		public PCAPPacketHeader(InputStream is) throws IOException {
			header = new byte[16];
			try {
				if (is.read(header) < 0)
					throw new EOFException();
			} catch (EOFException e) { // EOFException extends IOException so would be caught by the catch(IOException)...
				throw e;
			} catch (IOException e) {
				throw new IOException(e.getMessage());
			}
			ByteBuffer buf = ByteBuffer.wrap(header);
			buf.order(ByteOrder.LITTLE_ENDIAN); // Little Endian for PCAP Header
			try {
				ts_sec = readUINT32(buf);
				ts_usec = readUINT32(buf);
				includedLength = readUINT32(buf);
				originalLength = readUINT32(buf);
			} catch (BufferUnderflowException e) {
				throw new IOException(e.getMessage());
			}
			buf = null;
			if (includedLength < 0)
				throw new IOException("Invalid 'includedLength' "+includedLength);
		}
		
		public byte[] getHeaderData() {
			return header;
		}
		
	}
	
	
	/** The {@code InputStream} to read packets from. */
	private InputStream is;
	
	/** The {@code PCAPDump} responsible to dump packets, or {@code null} if no dump is needed. */
	private PCAPDump dump;
	
	private PCAPHeader pcapHeader;
	private PCAPPacketHeader pcapPacket;
	private byte[] netData;
	
	private int packetNum;
	
	public PCAPReader(InputStream is, PCAPDump dump) throws IOException {
		this.is = is;
		this.dump = dump;
		pcapHeader = new PCAPHeader(is);
		if (dump != null)
			dump.setPCAPFileHeader(pcapHeader);
		packetNum = 0;
	}
	
	public PCAPReader(InputStream is) throws IOException {
		this(is, null);
	}
	
	public void setPCAPDump(PCAPDump dump) {
		this.dump = dump;
	}
	
	/**
	 * @return The next packet in the InputStream, or {@code null} if end of stream was reached.
	 * @throws IOException if the packet cannot be decoded. That does NOT necessarily means that
	 * 		no other packets can be read!
	 */
	public Packet readNextPacket() throws IOException {
		int szNet = 0;
		pcapPacket = new PCAPPacketHeader(is);
		
		// Read total packet into a byte buffer and use it for decoding
		netData = new byte[pcapPacket.includedLength];
		try {
			if (is.read(netData) < 0)
				return null;
		} catch (IOException e) {
			throw new IOException(e.getMessage());
		}
		// Dump back the packet right after reading its data, before decoding
		if (dump != null) {
			try {
				dump.writePacketPCAPData(pcapPacket, netData);
			} catch (IOException e) {
				System.err.println(e.getMessage());
			}
		}
		ByteBuffer buf = ByteBuffer.wrap(netData);
		
		pcapPacket.packetNum = ++packetNum; // Packet header was read correctly
		EthernetFrame ethernetFrame = new EthernetFrame(buf);
		IPv4Frame ip4;
		TCPFrame tcpFrame = null;
		UDPFrame udpFrame = null;
		
		szNet += ethernetFrame.getHeaderSize();
		switch (ethernetFrame.ethertype) {
			case NetworkFrame.ETHERTYPE_IPV4:
				ip4 = new IPv4Frame(buf);
				szNet += ip4.getHeaderSize();
				break;
				
			default:
				throw new IOException(String.format("Unhandled ethertype %d!", ethernetFrame.ethertype));
		}
		
		switch (ip4.protocol) {
			case NetworkFrame.PROTOCOL_TCP:
				tcpFrame = new TCPFrame(buf);
				szNet += tcpFrame.getHeaderSize();
				break;
				
			case NetworkFrame.PROTOCOL_UDP:
				udpFrame = new UDPFrame(buf);
				szNet += udpFrame.getHeaderSize();
				break;
			
			default:
				throw new IOException(String.format("Unhandled protocol %d!", ip4.protocol));
		}
		
		byte[] data = new byte[buf.remaining()]; // Should be 'pcapPacket.includedLength - szNet'
		try {
			buf.get(data);
		} catch (BufferUnderflowException e) {
			throw new IOException(e.getMessage());
		}
		buf = null;
		
		return new Packet(pcapPacket, ethernetFrame, ip4, tcpFrame, udpFrame, packetNum, data, pcapPacket.originalLength - szNet);
	}
	
	/**
	 * @return The number of the last packet read, including undecoded packets.
	 */
	public int getLastPacketNumber() {
		return packetNum;
	}
	
	/**
	 * @return The snap length of the PCAP file (maximum number of bytes recorded per packet).
	 */
	public int getSnapLength() {
		return pcapHeader.snaplen;
	}

	public void close() {
		if (is != null && is != System.in) {
			try {
				is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		if (dump != null)
			dump.close();
	}
}
