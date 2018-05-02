package pcap;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import pcap.PCAPReader.PCAPHeader;
import pcap.PCAPReader.PCAPPacketHeader;

public class PCAPDump {

	/** The base filename for dump files. */
	private String dumpName;
	
	/** Maximum size of a dump file, in bytes. */
	private long dumpMaxSize;
	
	/** Maximum number of dump file to be created. */
	private int dumpMaxNum;
	
	/** The current dump file number. */
	private int dumpNum;
	
	/** Current dump size, in bytes. */
	private long dumpCurSize;
	
	/** PCAP file header to be written at the beginning of each PCAP file. */
	private PCAPHeader pcapHeader;
	
	/** The {@code OutputStream} to write decoded PCAP to. */
	private OutputStream os;
	
	public PCAPDump(String dumpName, long dumpMaxSize, int dumpMaxNum) {
		this.dumpName = dumpName;
		this.dumpMaxSize = dumpMaxSize;
		this.dumpMaxNum = dumpMaxNum;
		dumpNum = 0;
		dumpCurSize = 0l;
	}
	
	public PCAPDump() {
		this(null, 0, 0);
	}
	
	public void setDumpName(String dumpName) {
		this.dumpName = dumpName;
	}
	
	public void setDumpMaxSize(long dumpMaxSize) {
		this.dumpMaxSize = dumpMaxSize;
	}
	
	public void setDumpMaxNumber(int dumpMaxNum) {
		this.dumpMaxNum = dumpMaxNum;
	}
	
	public void setPCAPFileHeader(PCAPHeader pcapHeader) {
		this.pcapHeader = pcapHeader;
	}
	
	private boolean startNewDump() throws IOException {
		if (dumpName == null)
			return true;
		
		if (pcapHeader == null)
			return false;
		
		if (os != null) {
			try {
				os.close();
			} catch (IOException e) {
				System.err.println(e.getMessage());
				return false;
			}
		}
		
		// Remove previous dumps
		if (dumpMaxNum > 0 && dumpNum >= dumpMaxNum) {
			File toRemove = new File(String.format("%s.%03d.pcap", dumpName, dumpNum - dumpMaxNum));
			if (toRemove.exists())
				toRemove.delete();
		}
		
		try {
			String fileName = String.format(dumpMaxNum > 0 ? "%s.%03d.pcap" : "%s.pcap", dumpName, dumpNum++);
			os = new BufferedOutputStream(new FileOutputStream(fileName));
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
			os = null;
			return false;
		}
		
		byte[] data = pcapHeader.getHeader();
		os.write(data);
		dumpCurSize = data.length;
		
		return true;
	}
	
	public boolean writePacketPCAPData(PCAPPacketHeader pcapHeader, byte[] pcapData) throws IOException {
		if (os == null && !startNewDump())
			return false;
		
		byte[] data = pcapHeader.getHeaderData();
		if (dumpMaxSize > 0l && dumpCurSize + data.length + pcapData.length > dumpMaxSize && !startNewDump())
			return false;
		
		os.write(data);
		dumpCurSize += data.length;
		os.write(pcapData);
		dumpCurSize += pcapData.length;
		
		return true;
	}

	public void close() {
		if (os != null) {
			try {
				os.close();
			} catch (IOException e) {
				System.err.println(e.getMessage());
			}
		}
	}
	
}
