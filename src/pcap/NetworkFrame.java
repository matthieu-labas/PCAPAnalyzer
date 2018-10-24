package pcap;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * Class containing definitions of all relevant network frames headers.
 * See:
 * - PCAP file format     : http://wiki.wireshark.org/Development/LibpcapFileFormat
 * - Ethernet frame header: http://en.wikipedia.org/wiki/Ethernet_frame
 * - IPv4 header          : http://en.wikipedia.org/wiki/IPv4_header
 * - TCP header           : http://en.wikipedia.org/wiki/Transmission_Control_Protocol
 * - UDP header           : http://en.wikipedia.org/wiki/User_Datagram_Protocol
 * - List of link types         : http://www.tcpdump.org/linktypes.html
 * - List of Ethertypes         : http://en.wikipedia.org/wiki/EtherType
 * - List of IP protocol numbers: http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
 * 
 * @author Matthieu Labas
 */
public abstract class NetworkFrame {
	
	public final static int ETHERTYPE_IPV4 = 0x800;
	
	public final static int PROTOCOL_TCP = 0x06;
	public final static int PROTOCOL_UDP = 0x11;
	public final static int PROTOCOL_IGMP = 0x02;
	
	public abstract int getHeaderSize();
	
	
	public static class EthernetFrame extends NetworkFrame {
		
		public byte[] srcMAC;
		public byte[] dstMAC;
		public int qtag;
		public int ethertype;
		
		public EthernetFrame(ByteBuffer buf) throws IOException {
			try {
				srcMAC = new byte[6];
				buf.get(srcMAC);
				dstMAC = new byte[6];
				buf.get(dstMAC);
				qtag = PCAPReader.readUINT16(buf);
				if (qtag != 0x8100) {
					ethertype = qtag;
					qtag = 0;
				} else {
					qtag = qtag << 16 | PCAPReader.readUINT16(buf);
					ethertype = PCAPReader.readUINT16(buf);
				}
				if (ethertype < 1536)
					throw new IOException(String.format("Unhandled ethertype %d as length!", ethertype));
			} catch (BufferUnderflowException e) {
				throw new IOException(e.getMessage());
			}
		}
		
		@Override
		public int getHeaderSize() {
			return isQTagged() ? 18 : 14;
		}
		
		public boolean isQTagged() {
			return qtag >> 16 == 0x8100;
		}
		
		public String formatMAC(byte[] mac) {
			return String.format("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		}
		
		public String formatSourceMAC() {
			return formatMAC(srcMAC);
		}
		
		public String formatDestinationMAC() {
			return formatMAC(dstMAC);
		}
		
		@Override
		public String toString() {
			return String.format("%s > %s ethertype %04x", formatSourceMAC(), formatDestinationMAC(), ethertype);
		}
	}
	
	public static class IPv4Frame extends NetworkFrame {
		
		public int version;
		public int ihl;
		public int dscpEnable;
		public int totalLen;
		public int ident;
		public int flags;
		public int fragOffset;
		public int ttl;
		public int protocol; /* One of PROTOCOL_* */
		public int checksum;
		public Inet4Address srcIP;
		public Inet4Address dstIP;
		public byte[] options;
		
		public IPv4Frame(ByteBuffer buf) throws IOException {
			byte[] ip = new byte[4];
			try {
				int data = PCAPReader.readUINT8(buf);
				version = data >> 4;
				ihl = data & 0xf;
				//if (ihl < 5)
				//	throw new NegativeArraySizeException(String.format("Bad IHL '%d' IPv%d source %s dest %s len %d checksum %02x", ihl, version, srcIP, dstIP, totalLen, checksum));
				dscpEnable = PCAPReader.readUINT8(buf);
				totalLen = PCAPReader.readUINT16(buf);
				ident = PCAPReader.readUINT16(buf);
				data = PCAPReader.readUINT16(buf);
				flags = data >> 13;
				fragOffset = 8 * (data & 0x1fff);
				ttl = PCAPReader.readUINT8(buf);
				protocol = PCAPReader.readUINT8(buf);
				checksum = PCAPReader.readUINT16(buf);
				try {
					buf.get(ip);
					srcIP = (Inet4Address)InetAddress.getByAddress(ip);
					buf.get(ip);
					dstIP = (Inet4Address)InetAddress.getByAddress(ip);
				} catch (UnknownHostException e) {
					throw new IOException(e.getMessage());
				}
				if (ihl > 5) { // Optional "options" field
					options = new byte[4*ihl-20];
					buf.get(options);
				}
			} catch (BufferUnderflowException e) {
				throw new IOException(e.getMessage());
			}
		}
		
		@Override
		public int getHeaderSize() {
			return 4 * ihl;
		}
		
		public boolean isFragmented() {
			return (flags & 0x1) == 0x1;
		}
		
		public boolean isFragment() {
			return fragOffset > 0;
		}
		
		@Override
		public String toString() {
			return String.format("%s > %s len %d", srcIP.getHostAddress(), dstIP.getHostAddress(), totalLen);
		}
	}
	
	public static class TCPFrame extends NetworkFrame {
		public int src_port;
		public int dstPort;
		public int seqnum;
		public int acknum;
		public int data_off;
		public int flags;
		public int window_size;
		public int checksum;
		public int urgentptr;
		public int[] options;
		
		public TCPFrame(ByteBuffer buf) throws IOException {
			try {
				src_port = PCAPReader.readUINT16(buf);
				dstPort = PCAPReader.readUINT16(buf);
				seqnum = PCAPReader.readUINT32(buf);
				acknum = PCAPReader.readUINT32(buf);
				data_off = PCAPReader.readUINT8(buf) >> 4;
				flags = PCAPReader.readUINT8(buf);
				window_size = PCAPReader.readUINT16(buf);
				checksum = PCAPReader.readUINT16(buf);
				urgentptr = PCAPReader.readUINT16(buf);
				if (data_off > 5) {
					options = new int[data_off - 5]; // (4*data_off-20) / 4 (number of 32-bits words)
					for (int i = 0; i < options.length; i++)
						options[i] = PCAPReader.readUINT32(buf);
				}
			} catch (BufferUnderflowException e) {
				throw new IOException(e.getMessage());
			}
		}
		
		@Override
		public int getHeaderSize() {
			return 4 * data_off;
		}
		
		@Override
		public String toString() {
			return String.format(":%d > :%d", src_port, dstPort);
		}
	}
	
	public static class UDPFrame extends NetworkFrame {
		public int srcPort;
		public int dstPort;
		public int len;
		public int checksum;
		
		public UDPFrame(ByteBuffer buf) throws IOException {
			try {
				srcPort = PCAPReader.readUINT16(buf);
				dstPort = PCAPReader.readUINT16(buf);
				len = PCAPReader.readUINT16(buf);
				checksum = PCAPReader.readUINT16(buf);
			} catch (BufferUnderflowException e) {
				throw new IOException(e.getMessage());
			}
		}
		
		@Override
		public int getHeaderSize() {
			return 8;
		}
		
		@Override
		public String toString() {
			return String.format(":%d > :%d len %d", srcPort, dstPort, len);
		}
	}
	
}
