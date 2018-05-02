package pcap.filters;


/**
 * Abstract PCAPFilter class implementing the logical name {@link MessageFilter#setName(String)}
 * method.<br/>
 * Basic Filter class can extend it and implement the other methods.
 * 
 * @author Matthieu Labas
 */
public abstract class AbstractMessageFilter implements MessageFilter {
	
	/**
	 * The logical name of the Filter.
	 */
	protected String name;
	
	/**
	 * The alternate code.
	 */
	protected String altCode;
	
	protected FilterPrinter printer;
	
	@Override
	public MessageFilter duplicate() {
		try {
			MessageFilter filter = getClass().newInstance();
			filter.setName(name);
			filter.setAlternateCode(altCode);
			filter.setPrinter(printer);
			return filter;
		} catch (InstantiationException e) {
			return null;
		} catch (IllegalAccessException e) {
			return null;
		}
	}
	
	@Override
	public void setName(String name) {
		this.name = name;
	}
	
	@Override
	public String getName() {
		return name;
	}
	
	@Override
	public void setAlternateCode(String code) {
		altCode = code;
	}
	
	@Override
	public String getAlternateCode() {
		return altCode;
	}
	
	@Override
	public void setPrinter(FilterPrinter printer)  {
		this.printer = printer;
	}
	
	/**
	 * Helper method for Filters to print regular information.
	 * @param format The format String to print.
	 * @param args The arguments to fill in {@code format}.
	 * @see String#format(String, Object...)
	 */
	public void print(String format, Object ... args) {
		if (printer != null)
			printer.filterPrint(this, format, args);
	}

	/**
	 * Helper method for Filters to print verbose (packet-level) information.
	 * @param format The format String to print.
	 * @param args The arguments to fill in {@code format}.
	 * @see String#format(String, Object...)
	 */
	public void printVerbose(String format, Object ... args) {
		if (printer != null)
			printer.filterPrintVerbose(this, format, args);
	}
	
	@Override
	public void reset() { }
	
}
