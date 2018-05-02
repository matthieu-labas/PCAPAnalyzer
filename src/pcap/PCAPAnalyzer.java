package pcap;

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.URL;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import pcap.filters.FilterPrinter;
import pcap.filters.MessageFilter;
import pcap.filters.impl.Empty;
import pcap.filters.impl.PrintAll;
import pcap.filters.impl.RTP;
import pcap.filters.impl.Stat;
import pcap.filters.impl.StatDest;
import pcap.filters.impl.StatSource;

/**
 * Main class performing PCAP stream analysis.
 * Can be used piped to tcpdump/windump:
 * <pre>tcpdump -Uw - | PCAPAnalyzer ...</pre>
 * (N.B. that {@code -U} has to be used to correctly buffer output).<br/>
 * N.B. when using {@code WinDump} (tcpdump for Windows: {@link "http://www.winpcap.org/windump"}),
 * list of Network Interface can be retrieved through {@code WinDump -D}.
 * 
 * @author Matthieu Labas
 */
public class PCAPAnalyzer implements FilterPrinter {
	
	/* Version	Date		Author			Comment
	 * 1.0		11/09/2013	Matthieu Labas	Creation. UDP handling.
	 * 			12/09/2013	Matthieu Labas	Redone log macros. Added debug logs. Parsed command line.
	 * 			13/09/2013	Matthieu Labas	Added Selectors and Filters linking concepts.
	 * 1.0		16/09/2013	Matthieu Labas	Ported to Java
	 * 			17/09/2013	Matthieu Labas	Added FIFO to check for duplicates and reordered packets.
	 * 1.1		18/09/2013	Matthieu Labas	Added source/destination IP Filter. Use memory buffer to
	 * 										read PCAP packets while parsing is done through a ByteBuffer
	 * 										instead of InputStream. It is faster and more reliable.
	 * 										Added option "-v" to enable Filters to display packet-related
	 * 										information. Added option "-dump" to dump PCAP output to
	 * 										a file.
	 * 1.2		22/09/2013	Matthieu Labas	Added -join option to register on multicast address.
	 * 1.3		24/09/2013	Matthieu Labas	Dump writes done in "finally" blocks. Indication of max nlost in
	 * 										a row, and position reordering.
	 * 1.4		29/09/2013	Matthieu Labas	Added option to have rotating dump file.
	 * 			02/10/2013	Matthieu Labas	Watch give analysis on packets between two watch on several Filters.
	 * 1.5		07/10/2013	Matthieu Labas	Added option to capture packets between start and end dates.
	 * 										Added Track Filter.
	 * 1.6		08/10/2013	Matthieu Labas	Filter RawVideo prints detailed information in watch.
	 * 1.6.1	11/10/2013	Matthieu Labas	Added number of lost packets to number of received packets to
	 * 										compute the percentage packets.
	 * 1.7		13/10/2013	Matthieu Labas	Packets with unknown format are still dumped to dump file.
	 * 2.0		30/10/2013	Matthieu Labas	Watch are handled through separate Filters in Selector (much cleaner).
	 * 										Handling fragmented packets. Refactored dump into a separate class.
	 */
	public static final String VERSION = "2.0";
	
	/**
	 * Default location of Filters when trying to instantiate a non-registered Filter.<br/>
	 * Such Filters <strong>have to</strong> provide a no-arguments Constructor.
	 */
	public static final String FILTERS_PACKAGE = "pcap.filters.impl";
	
	private static Map<String,Class<?>> filters = new LinkedHashMap<String,Class<?>>();
	private static Map<Class<?>,String> filtersCodes = new LinkedHashMap<Class<?>,String>();
	private static Map<String,String> filtersDescr = new LinkedHashMap<String,String>();
	
	/**
	 * Property name controlling the reordering/duplication FIFO size.
	 * @see #DEFAULT_REORDUPL_WINDOW
	 */
	public static final String REORDUPL_PROP = "reordupl";
	
	/**
	 * Default window size for packet FIFO to check for duplicates and reordering.<br/>
	 * This value can either be changed programatically before instantiating a Counter Filter or
	 * by setting the {@code "reordupl"} System property ({@code java -Dreordupl=50 ...}).
	 * @see #REORDUPL_PROP
	 */
	public static int DEFAULT_REORDUPL_WINDOW = 100;
	static {
		try {
			DEFAULT_REORDUPL_WINDOW = Integer.parseInt(System.getProperty(REORDUPL_PROP));
		} catch (NumberFormatException e) { }
	}
	
	static {
		// TODO: Register all built-in Filters here
		registerBuiltinFilter(Empty.class, Empty.DESCRIPTION);
		registerBuiltinFilter(PrintAll.class, "PRINT", PrintAll.DESCRIPTION);
		registerBuiltinFilter(Stat.class, Stat.DESCRIPTION);
		registerBuiltinFilter(RTP.class, RTP.DESCRIPTION);
		registerBuiltinFilter(StatSource.class, "STATSRC", StatSource.DESCRIPTION);
		registerBuiltinFilter(StatDest.class, "STATDST", StatDest.DESCRIPTION);
	}
	
	public static boolean registerBuiltinFilter(Class<?> filterClass, String code, String description) {
		if (!MessageFilter.class.isAssignableFrom(filterClass)) { // Class must implement the PCAPFilter interface
			System.err.println(String.format("Class '%s' does not implement Filter interface '%s'!",
					filterClass.getName(), MessageFilter.class.getName()));
			return false;
		}
		
		if (code == null)
			code = filterClass.getSimpleName();
		code = code.toUpperCase();
		Class<?> cls = filters.put(code, filterClass);
		if (cls != null)
			System.out.println(String.format("Class '%s' replaces '%s' as definition of Filter '%s'!",
					filterClass.getName(), cls.getName(), code));
		filtersCodes.put(filterClass, code);
		filtersDescr.put(code, description);
		
		return true;
	}
	
	public static boolean registerBuiltinFilter(Class<?> filterClass, String description) {
		return registerBuiltinFilter(filterClass, null, description);
	}
	
	public static MessageFilter createFilterIntance(String codeAndName) {
		String[] codeName = codeAndName.split(":", 2);
		String code = codeName[0].toUpperCase();
		String name = (codeName.length == 2 ? codeName[1] : null);
		// Looks up the code in the Filter table
		Class<?> cls = filters.get(code);
		
		if (cls == null) { // Code not found, try to instantiate from the code as class name in default Filter package
			try {
				cls = Class.forName(FILTERS_PACKAGE+codeName[0]);
			} catch (ClassNotFoundException e) { // Class not found in default Filter package, try code as absolute class name
				try {
					cls = Class.forName(codeName[0]);
				} catch (ClassNotFoundException e1) {
					System.err.println(String.format("Filter '%s' cannot be found!", codeName[0]));
					return null;
				}
			}
			filters.put(code, cls);
		}
		
		// Now that we have the class, try to instantiate it
		MessageFilter filter;
		try {
			filter = (MessageFilter)cls.newInstance();
		} catch (ClassCastException e) { // Does not implement PCAPFilter interface
			System.err.println(String.format("Class '%s' is not a Filter!", cls.getName()));
			return null;
		} catch (InstantiationException e) { // Does not have an empty constructor?
			System.err.println(String.format("Unable to instantiate Filter class '%s'! Does it define an empty Constructor?",
					cls.getName()));
			return null;
		} catch (IllegalAccessException e) {
			e.printStackTrace();
			return null;
		}
		
		// Finally, sets the logical name of the Filter
		filter.setName(name);
		
		return filter;
	}

	/** The shutdown hook called when {@code Ctrl+C} is pressed. */
	private Thread shutdownHook;
	
	/** {@code true} if Filters are allowed to be verbose (print information on-the-fly). */
	private boolean printVerbose;
	
	/** The PCAP decoder. */
	private PCAPReader reader;
	
	/** The FIFO storing packets to reorder fragments (in case intermediate packets are received
	 * between a first UDP and its fragments). */
	private LinkedList<Packet> fragFIFO;
	
	/** Number of fragmented packets lost. */
	private int nFragmentsLost;
	
	/** Number of packets getting out of {@link #fragFIFO} when not all its fragments are received. */
	private int nUnfinishedPackets;
	
	/** List of Selectors processing packets. */
	private List<Selector> selectors;
	
	/** List of Multicast groups joined. */
	private Map<MulticastSocket,InetAddress> groups;
	
	/** Time (ms) when capture started. */
	private long t0;
	
	public PCAPAnalyzer() {
		shutdownHook = null;
		selectors = new LinkedList<Selector>();
		groups = new HashMap<MulticastSocket,InetAddress>();
		fragFIFO = new LinkedList<Packet>();
		nFragmentsLost = 0;
		nUnfinishedPackets = 0;
	}
	
	/**
	 * Creates an instance of the Analyzer using a specific {@code InputStream} to decode PCAP.
	 * @param is The PCAP input stream.
	 * @param dump Object to dump PCAP frames to.
	 * @throws IOException if the input stream is not of PCAP format.
	 */
	public PCAPAnalyzer(InputStream is, PCAPDump dump) throws IOException {
		this();
		setInputStreamAndStart(is, dump);
	}
	
	public boolean joinGroup(String multicastAddress) {
		MulticastSocket s;
		InetAddress group;
		try {
			s = new MulticastSocket();
			group = InetAddress.getByName(multicastAddress);
			s.joinGroup(group);
			groups.put(s, group);
			return true;
		} catch (IOException e) {
			System.err.println("Unable to join multicast address "+multicastAddress+"!: "+e.getMessage());
			return false;
		}
	}
	
	public void setInputStreamAndStart(InputStream is, PCAPDump dump) throws IOException {
		try {
			reader = new PCAPReader(is, dump);
		} catch (EOFException e) {
			throw new IOException("EOF detected in InputStream!");
		}
		t0 = System.currentTimeMillis();
	}
	
	public void setInputStreamAndStart(InputStream is) throws IOException {
		setInputStreamAndStart(is, null);
	}
	
	/**
	 * @return The shutdown hook to be called upon exit or signal interruption. N.B. that this method
	 *     returns a singleton instance of {@code Thread}: calling it several time will always return
	 *     the same instance.
	 */
	public Thread getShutdownHook() {
		if (shutdownHook == null) {
			shutdownHook = new Thread() {
				@Override
				public void run() {
					PCAPAnalyzer.this.finish();
				}
			};
		}
		return shutdownHook;
	}
	
	/**
	 * Cleans-up, closing the input-stream.
	 */
	public void finish() {
		for (Entry<MulticastSocket,InetAddress> e : groups.entrySet()) {
			try {
				e.getKey().leaveGroup(e.getValue());
			} catch (IOException e1) { }
		}
		
		if (reader != null)
			reader.close(); // Closes input and output streams
		
		// Empty fragmentation FIFO
		for (Packet packet : fragFIFO)
			processPacket(packet);
		
		// Call finish() on all Filters of all Selectors
		for (Selector selector : selectors)
			selector.finish();
		
		t0 = System.currentTimeMillis() - t0;
		
		if (nFragmentsLost > 0 || nUnfinishedPackets > 0)
			System.out.println(String.format("%d fragments lost, %d unfinished packets (increase FIFO size?).", nFragmentsLost, nUnfinishedPackets));
		
		int lastPacket = getLastPacketNumber();
		if (lastPacket >= 0)
			System.out.println(String.format("[Processed %d packets in %.3f s (%.3f packets/s)].",
					getLastPacketNumber(), t0 / 1000.0, 1000.0 * getLastPacketNumber() / t0));
	}
	
	/**
	 * @return The next packet decoded from the PCAP stream, or {@code null} if the end of stream was
	 *     reached.
	 * @throws IOException If the packet could not be decoded. N.B. that is does NOT necessarily means
	 * 		that no more packets can be decoded!
	 * @throws NullPointerException If {@link #setInputStreamAndStart(InputStream, PCAPDump)} has not been called.
	 * @throws EOFException When EOF has been reached.
	 * @see PCAPReader#readNextPacket()
	 */
	public Packet getNextPacket() throws IOException {
		if (reader == null)
			throw new NullPointerException("No InputStream has been set!");
		Packet p = null;
		
		p = reader.readNextPacket();
		if (!p.isFragmented() && fragFIFO.isEmpty()) // Packet is not fragmented and fragmentation FIFO is empty: return the packet directly. Otherwise we maintain packet order
			return p;
		
		// 'p' is fragmented or fragFIFO is not empty
		
		// If 'p' is a fragment, look up the "main" packet to merge it
		if (p.isFragment()) {
			boolean found = false;
			for (Iterator<Packet> iter = fragFIFO.iterator(); iter.hasNext();) {
				Packet pFIFO = iter.next();
				if (pFIFO.mergeWith(p)) { // Returns true if 'p' is a next fragment of 'pFIFO' and merge it
					found = true;
					p = null; // Discard packet (was merged into pFIFO)
					break;
				}
			}
			if (!found) { // Main packet not found: lost?
				nFragmentsLost++;
				throw new IOException(String.format("Packet #%d: cannot find initial packet of fragment ID 0x%x! Discarded...", p.getPacketNumber(), p.getIPID()));
			}
		}
		
		// Add packet to FIFO
		if (p != null)
			fragFIFO.offer(p);
		p = fragFIFO.peek();
		if (!p.expectMoreFragments())
			return fragFIFO.pop();
		
		if (fragFIFO.size() > DEFAULT_REORDUPL_WINDOW) {
			p = fragFIFO.pop(); // Return the first available packet even if more fragments are expected (will lead to nFragmentsLost > 0) 
			if (p.expectMoreFragments())
				nUnfinishedPackets++;
			return p;
		}
		
		return null; // FIFO filling up
		
//		Packet pfrag = null;
//		do { // Read a packet. If it is fragmented, initializes 'pfrag' with it and keep reading
//			p = reader.readNextPacket();
//			if (pfrag != null)
//				pfrag.mergeWith(p);
//			else
//				pfrag = p;
//		} while (p.isFragmented());
//		return pfrag;
	}
	
	/**
	 * @return The number of the last packet read, including undecoded packets.
	 * @throws NullPointerException If {@link #setInputStreamAndStart(InputStream)} has not been called.
	 * @see PCAPReader#getLastPacketNumber()
	 */
	public int getLastPacketNumber() {
		if (reader == null)
			return -1;
		return reader.getLastPacketNumber();
	}
	
	public void addSelectors(List<Selector> selectors) {
		this.selectors.addAll(selectors);
	}
	
	public Selector addSelector(Selector selector) {
		return selectors.add(selector) ? selector : null;
	}
	
	/**
	 * @return The list of active Selectors to process packets.
	 */
	public List<Selector> getSelectors() {
		return selectors;
	}
	
	/**
	 * Sends a packet through all Selectors and return the number of Selectors which processed the
	 * packet.
	 * @param packet The packet to be processed by the list of Selectors.
	 * @return The number of Selectors activated by the packet.
	 */
	public int processPacket(Packet packet) {
		int nSelProcess = 0;
		for (Selector selector : selectors)
			if (selector.acceptsPacket(packet))
				if (selector.process(packet) > 0)
					nSelProcess++;
		return nSelProcess;
	}
	
	/**
	 * Enable watch on all Selectors.
	 * @see Selector#enableWatch()
	 */
	public void enableWatch() {
		for (Selector selector : selectors)
			selector.enableWatch();
	}
	
	/**
	 * Call {@link MessageFilter#watch()} on all Filters of all Selectors.
	 */
	public void watch() {
		for (Selector selector : selectors)
			selector.watch();
	}
	
	@Override
	public void setFilterVerbose(boolean verbose) {
		printVerbose = verbose;
	}
	
	@Override
	public void filterPrint(MessageFilter filter, String format, Object... args) {
		String name = filter.getName();
		name = (name == null ? "" : ":"+name);
		String code = filtersCodes.get(filter.getClass());
		if (code == null)
			code = filter.getAlternateCode();
		String head = String.format("[%s%s]: ", code, name);
		String sep = String.format("%"+head.length()+"s", " ");
		String str = String.format(format, args); // format.replace("%", "%%")
		String[] tab = str.split("\n");
		System.out.println(head+tab[0]);
		for (int i = 1; i < tab.length; i++)
			System.out.println(sep+tab[i]);
	}
	
	@Override
	public void filterPrintVerbose(MessageFilter filter, String format, Object... args) {
		if (!printVerbose)
			return;
		filterPrint(filter, format, args);
	}
	
	
	public static void printUsage(String prog) {
		System.out.println("    [-h|--help]                                 Display usage");
		System.out.println("    [--version]                                 Display version");
		System.out.println("    [--list-filters]                            Display available Filters");
		System.out.println("    [-v]                                        Verbose output for Filters");
		System.out.println("    [-join <multicast address>]                 Register on a multicast address (can have several)");
		System.out.println("    [-select <sel param> <filter[:name][,...]>] Add Selector (can have several)");
		System.out.println("    [-watch <s>]                                Specify Selectors watch period (s, default: 0(none))");
		System.out.println("    [pcap file] (default: stdin)                PCAP file to parse");
		System.out.println("    [-dump <pcap file>]                         Dump PCAP data read to a file");
		System.out.println("    [-dumprot <size[:number]>]                  Max dump file size (MB) and number of rotating dump files");
		System.out.println("    [-timespan <[start]:end>]                   Specify capture start/end time in format YYYY-MM-DD-HH-mm-ss");
		System.out.println("---");
		System.out.println("\"sel param\" is a string like \"[<TCP|UDP>$][srcIP|ANY][:port]=[dstIP|ANY][:port]\"");
		System.out.println("    e.g.: \"=230.116.1.1\" to receive packet sent to multicast address \"230.116.1.1\"");
		System.out.println("    e.g.: \"UDP$10.116.4.41=\" to process UDP packets sent by IP \"10.116.4.41\"");
		System.out.println("    e.g.: \"10.116.4.41\" to process any packets sent by or to IP \"10.116.4.41\"");
		System.out.println("\"filter list\" is comma-separated list of registered Filters, with optional name (after ':')");
		System.out.println("    e.g.: \"RTP:Cam1,STAT\"");
		System.out.println("---");
		System.out.println("Examples:");
		System.out.println("\""+prog+" -select 230.115.1.1 RAWVID:C8 -select 230.116.1.1 RAWVID:C9\"");
		System.out.println("    To process packets sents to multicast address \"230.115.1.1\" with filter \"RAWVID\" named \"C8\" \"230.116.1.1\" with filter \"RAWVID\"");
		System.out.println("    and packets sents to multicast address \"230.116.1.1\" with filter \"RAWVID\" named \"C9\"");
		System.out.println("\""+prog+"%s -select 10.10.4.4=225.1.2.3:29866 SN,STAT");
		System.out.println("    To process packets sent by IP \"10.10.4.4\" to multicast address \"225.1.2.3:29866\" with filters \"SN\" and \"STAT\"");
	}
	
	public static void printVersion() {
		String path = PCAPAnalyzer.class.getName();
		path = path.substring(path.lastIndexOf('.')+1)+".class";
		URL fileURL = PCAPAnalyzer.class.getResource(path);
		String date = "";
		try {
			date = String.format(" (%s)", new Date(fileURL.openConnection().getLastModified()));
		} catch (IOException e) { }
		System.out.println(String.format("Version %s%s", VERSION, date));
	}
	
	public static void printAvailableFilters() {
		String descr;
		System.out.println("Available Filters:");
		int sz = 0;
		for (String code : filters.keySet())
			sz = Math.max(sz, code.length());
		for (Entry<String,Class<?>> e : filters.entrySet()) {
			descr = filtersDescr.get(e.getKey());
			System.out.println(String.format("    %-"+sz+"s: %s.", e.getKey(), descr == null ? "(no description)" : descr));
		}
	}
	
	public static void main(String[] args) {
		PCAPAnalyzer pcapan = new PCAPAnalyzer();
		PCAPDump dump = null;
		String filenameIn = null;
		int watch = 0;
		long timeStart = -1l;
		long timeEnd = -1l;
		
		Runtime.getRuntime().addShutdownHook(pcapan.getShutdownHook());
		
		int nSelectors = 0;
		for (int i = 0; i < args.length; i++) {
			// Usage
			if (args[i].equalsIgnoreCase("-h") || args[i].equalsIgnoreCase("--help") || args[i].equalsIgnoreCase("-help")) {
				printUsage(PCAPAnalyzer.class.getSimpleName());
				System.exit(0);
			}
			
			// Usage
			if (args[i].equalsIgnoreCase("--version") || args[i].equalsIgnoreCase("-version")) {
				printVersion();
				System.exit(0);
			}
			
			// Filter list
			if (args[i].equalsIgnoreCase("--list-filters")) {
				printAvailableFilters();
				System.exit(0);
			}
			
			// Join multicast groups
			if (args[i].equalsIgnoreCase("-join")) {
				pcapan.joinGroup(args[++i]);
				continue;
			}
			
			// Selector
			if (args[i].equalsIgnoreCase("-select")) {
				Selector selector = new Selector(args[++i]);
				pcapan.addSelector(selector);
				
				MessageFilter filter;
				for (String fil : args[++i].split(",")) {
					filter = createFilterIntance(fil);
					if (filter == null) {
						System.err.println(String.format("Wrong Filter description '%s'", fil));
						continue;
					}
					filter.setPrinter(pcapan);
					selector.addFilter(filter);
				}
				continue;
			}
			
			if (args[i].equalsIgnoreCase("-watch")) {
				try {
					watch = 1000 * Integer.parseInt(args[++i]); // 'watch' is in ms
				} catch (NumberFormatException e) {
					System.err.println(String.format("'%s %s' is not a number!", args[i-1], args[i]));
					watch = 0;
				}
				continue;
			}
			
			// Filter verbosity
			if (args[i].equalsIgnoreCase("-v")) {
				pcapan.setFilterVerbose(true);
				continue;
			}
			
			// Output PCAP stream
			if (args[i].equalsIgnoreCase("-dump")) {
				if (dump == null)
					dump = new PCAPDump();
				dump.setDumpName(args[++i]);
				continue;
			}
			
			// Output PCAP stream file rotation
			if (args[i].equalsIgnoreCase("-dumprot")) {
				String[] param = args[++i].split(":");
				if (dump == null)
					dump = new PCAPDump();
				try {
					dump.setDumpMaxSize(Long.parseLong(param[0]) * 1024l*1024l);
					if (param.length > 1)
						dump.setDumpMaxNumber(Integer.parseInt(param[1]));
				} catch (NumberFormatException e) {
					System.err.println(String.format("Wrong %s option: %s", args[i-1], args[i]));
				}
				continue;
			}
			
			// Capture start/end time
			if (args[i].equalsIgnoreCase("-timespan")) {
				DateFormat df = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");
				String[] param = args[++i].split(":");
				if (param.length != 2) {
					System.err.println(String.format("Wrong %s option: %s (need ':' to separate both date/time)", args[i-1], args[i]));
					continue;
				}
				
				try {
					timeStart = (param[0].isEmpty() ? new Date().getTime() : df.parse(param[0]).getTime());
					timeEnd = df.parse(param[1]).getTime();
				} catch (ParseException e) {
					System.err.println(String.format("Wrong %s option: %s (%s)", args[i-1], args[i], e.getMessage()));
				}
				continue;
			}
			
			// Input stream
			if (filenameIn != null)
				System.out.println(String.format("File '%s' was already specified, it will be replace by '%s'.", filenameIn, args[i]));
			filenameIn = args[i];
		}
		
		if (watch > 0)
			pcapan.enableWatch();
		
		InputStream is = System.in;
		if (filenameIn != null) {
			System.out.println("Analyzing "+filenameIn);
			try {
				is = new FileInputStream(filenameIn);
			} catch (FileNotFoundException e) {
				System.err.println(e.getMessage());
				System.exit(1);
			}
		}
		
		try {
			pcapan.setInputStreamAndStart(is, dump);
		} catch (IOException e) {
			System.err.println("Unable to read from input stream: "+e.getMessage());
			System.exit(1);
		}
		
		long lastWatch = 0;
		long packetTimestamp;
		
		nSelectors = pcapan.getSelectors().size();
		int nPackets = 0;
		for (;;) {
			Packet packet;
			try {
				packet = pcapan.getNextPacket();
				nPackets++;
			} catch (EOFException e) {
				break;
			} catch (IOException e) {
				//System.err.println(String.format("Invalid format packet #%d: %s", pcapan.getLastPacketNumber(), e.getMessage()));
				continue;
			}
			if (packet == null) // FIFO is being filled, capture another packet
				continue;
			
			packetTimestamp = packet.getPacketTimeMillis();
			if (timeStart > 0 && timeEnd > 0) {
				if (packetTimestamp < timeStart)
					continue;
				if (packetTimestamp > timeEnd)
					break;
			}
			
			if (nSelectors == 0) // No Selectors defined: display packet
				System.out.println(packet);
			else {
				// Send packet to Selectors and Filters
				pcapan.processPacket(packet);
				// Send watch events according to packet timestamp
				if (watch > 0) {
					if (lastWatch == 0) {
						lastWatch = packetTimestamp;
					} else if (packetTimestamp - lastWatch > watch) {
						pcapan.watch();
						lastWatch = packetTimestamp;
					}
				}
			}
		}
		System.out.println(nPackets+" processed");
		
		// pcapan shutdown hook will be called at JVM exit
	}

}
