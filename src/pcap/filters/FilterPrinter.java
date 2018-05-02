package pcap.filters;

/**
 * Interface performing printing for Filter.
 * 
 * @author Matthieu Labas
 */
public interface FilterPrinter {
	
	/**
	 * Enable/Disable display of verbose messages from Filters.
	 * @param verbose {@code true} to enable verbose message display.
	 */
	void setFilterVerbose(boolean verbose);
	
	/**
	 * Method called by Filters to display regular information.
	 * @param filter The filter requesting display.
	 * @param format The format String to print.
	 * @param args The arguments to fill in {@code format}.
	 * @see String#format(String, Object...)
	 */
	public void filterPrint(MessageFilter filter, String format, Object... args);
	
	/**
	 * Method called by Filters to display verbose (packet-level) information.
	 * @param filter The filter requesting display.
	 * @param format The format String to print.
	 * @param args The arguments to fill in {@code format}.
	 * @see String#format(String, Object...)
	 */
	public void filterPrintVerbose(MessageFilter filter, String format, Object... args);
	
}
