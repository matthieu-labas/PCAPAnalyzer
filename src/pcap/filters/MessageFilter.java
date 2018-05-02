package pcap.filters;

import pcap.Packet;

public interface MessageFilter {
	
	/**
	 * Create a new instance of the current Filter, with the same parameters.<br/>
	 * This method is mainly used to create Watch Filters.
	 * @return A clone of the current Filter.
	 */
	MessageFilter duplicate();
	
	/**
	 * Sets the logical name of this specific Filter instance.
	 * @param name The logical name of this Filter instance.
	 */
	void setName(String name);
	
	/**
	 * @return The logical name of this Filter instance.
	 */
	String getName();
	
	/**
	 * Set an alternate code for inner-filters (not directly declared in the Filter list).
	 * @param code The new code.
	 */
	void setAlternateCode(String code);
	
	/**
	 * @return The alternate code for inner-filters.
	 */
	String getAlternateCode();
	
	/**
	 * @return A one-line description of the Filter behaviour.
	 */
	String getDescription();
	
	/**
	 * Sets the Printer to enable the Filter to print message (on console, file, ... according to
	 * the Printer implementation).
	 * @param printer The Printer to be used by the Filter to print information.
	 */
	void setPrinter(FilterPrinter printer);
	
	/**
	 * Method called whenever a packet should be processed by the Filter.
	 * @param packet The packet received.
	 * @return {@code true} if the packet matches the Filter, {@code false} otherwise.
	 */
	boolean process(Packet packet);
	
	/**
	 * Method called every once in a while to display intermediate statistics.
	 */
	void watch();
	
	/**
	 * For Watch Filters, reset internal state to prepare it for new watch.
	 */
	void reset();
	
	/**
	 * Method called when no more packets will be received. Housekeeping should be done here,
	 * as well as displaying statistics.
	 * @return {@code true} if no error occurred.
	 */
	boolean finish();
	
}
