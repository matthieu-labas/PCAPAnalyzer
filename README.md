# PCAP Analyzer

PCAP Analyzer is a tool that helps analyzing network traffic captured in a PCAP format (standard of tcpdump). It has extensible Filters in charge of dissecting packets and printing information like throughput or anything that can be analyzed by Filters (e.g. packet loss, reordering, ...).
It comes with several built-in Filters but can be expanded by adding custom-made Filters to the classpath.

It was developped to help understanding complex network routing problems, where packets could arrive out-of-order, some were lost, or duplicated.
Network analysis needed to synchronize capture on a local (destination) and remote (source) computers and display warning messages while recording traffic in PCAP format for offline analysis.

`PCAPAnalyzer` is typically used piped to `tcpdump` to show warnings on console, with the possibility to replay traffic later, with different Filters.

A "*select expression*" will first select packets based on TCP/UDP protocol, ip addresses and ports. Then, matching packets will be given to "*filters*" that will process packets with a knowledge of the underlying protocol (e.g. RTP, HTTP, custom-made, ...).


## Usage

    java -jar PCAPAnalyzer.jar [options] [PCAP input file]

### List of options :

`-h -help --help`<br/>
Show usage.

`-version --version`<br/>
Display version information.

`--list-filters`<br/>
Show the list of built-in Filters.

`-select <select expression> <filter list>`<br/>
Add a Selector with associated Filters.

`-join <multicast address>`<br/>
Joins the specified multicast address (useful when piping from tcpdump).

`-watch <watch period (s)>`<br/>
Display information periodically for each Selector/Filters (useful when piping from tcpdump).

`-v`<br/>
Allows Filters to display packet-level information (e.g. individual packet losses, ...) rather than at every watch or end of stream.

`-dump <PCAP dump file-prefix>`<br/>
Dumps all received traffic to another PCAP file (useful when piping from windump, as no tee command exists on Windows). To the file-prefix will be added `.001.pcap`

`-dumprot <size[:number]>`<br/>
Sets a rotation on dumps files to minimize impact on disk while keeping a history. The size specified is the maximum file size in MB. If a number is specified, it will automatically delete the older dumps.

`-timespan [start]<:end>`<br/>
Performs the capture between the specified dates in format `yyyy-MM-dd-HH-mm-ss`. If start is not provided, capture will start at once.
Useful to analyze streams originating from a computer toward another one: when these computers are synchronized through NTP, running the Analyzer on both using the same timespan will enable matching packet counts.

`-Dreordupl=<FIFO size>` (Java option, should be specified first)<br/>
Sets the size of the FIFO used to detect reordering and duplication (default is 100 packets). If its value is too small, big chunks of duplicates or packets arriving "very" late could be counted as lost.
This option should only be set when Counter Filters (such as RTP) are used.

---

N.B. If no PCAP input file is specified, standard input will be used (to pipe from tcpdump).

When piping from tcpdump (or windump on Windows), options `-Uw -` should be used to activate packet-buffering. Behaviour can be unpredictable otherwise:

    tcpdump -Uw - | tee out.pcap | java -jar PCAPAnalyzer.jar ...
    windump -Uw - | java -jar PCAPAnalyzer.jar -dump out.pcap ...


## Select expression

Such expressions will select specific network traffic and feed matching packets the filter list. Its syntax is:

`[protocol$][source IP[:port]]=[destination IP[:port]]`

where protocol is one of `TCP` or `UDP` and IP is an IPv4 (hostname or dotted IP) or `ANY` to match all IP addresses.

### Examples

`TCP$192.168.0.1:21=192.168.0.2:3162`<br/>
will select all TCP traffic going from IP 192.168.0.1, port 21 toward IP 192.168.0.2, port 3162

`192.168.0.1:21=192.168.0.2:3162`<br/>
will select all traffic (TCP or UDP) going from IP 192.168.0.1, port 21 toward IP 192.168.0.2, port 3162

`:21=192.168.0.2:3162`<br/>
`any:21=192.168.0.2:3162`<br/>
will select all traffic (TCP or UDP) going from any address on port 21 toward IP 192.168.0.2, port 3162

`=192.168.0.2:3162`<br/>
will select all traffic toward IP 192.168.0.2, port 3162

`192.168.0.2:3162`<br/>
will select all traffic toward or from IP 192.168.0.2, port 3162

## Filter list

The second parameter to a Select expression is a list of Filters which should receive corresponding packets and perform their analysis. As several Filter instances can coexist, it is possible to specify a *display name* to easier discriminate printed information. The syntax is:

`<filter code[:display name]>[,<filter code[:display name]>]...`

e.g. `RTP:Cam1,STAT:Cam1` will give all packets to two Filters `RTP` and `STAT` which displayed information will start like:

    [RTP:Cam1] ...
    [STAT:Cam1] ...

## Filters

### Built-in Filters

A few standard Filters are built in PCAP Analyzer:

`EMPTY`<br/>
Silently discards all packets, it is merely here as a base for other Filters.

`PRINT` `PRINTALL`<br/>
Prints all packets, giving the source IP:port, destination IP:port and data length.

`STAT`<br/>
Displays statistics about how many packets are received, throughput in packets/s and kiB/s.
This Filter can be the base of many other Filters as it keeps tracks of every packet received by the Filter.

`STATSRC` `STATSOURCE`<br/>
Prints statistics for every source IP detected in packet stream.

`STATDST` `STATDEST`<br/>
Prints statistics for every destination IP detected in packet stream.

`RTP`<br/>
Displays statistics about an RTP stream. This Filter derives AbstractCounterFilter that keeps track of packet loss, reordering and duplication.

### Adding custom Filters

In addition to existing built-in Filters, it is possible to program custom Filters either by implementing the `pcap.filters.MessageFilter` interface, or by extending an already-existing Filter. Such Filters should be added to the classpath when running PCAPAnalyzer. For the latter case, the `pcap.filters.AbstractMessageFilter` can be extended, as it implements default behaviour for common methods.

It is also possible to programatically register the new Filters and call `PCAPAnalyzer.main(args)`:

    import com.company.filters.impl.MyFilter;
    
    public class Dissecator {
        public static void main(String[] args) {
            PCAPAnalyzer.registerBuiltinFilter(MyFilter.class, "MYFILT", "My new Filter."); // Register custom Filters here
            PCAPAnalyzer.main(args); // Call the PCAPAnalyzer main program
        }
    }

To implement a custom Filter, the Class should be set in package `pcap.filters.impl`. The code used for the filter is simply the name of the Class:

`-select any MyFilt:name`<br/>
will try to instanciate class `pcap.filters.impl.MyFilt`.

Complete class name can also be used:

`-select any com.company.MyFilt:name`<br/>
will try to instanciate class `com.company.MyFilt`

**In all cases, Filters should implement a no-args Constructor!**

### Counter Filters

When a protocol (such as RTP) is known to have an embedded counter, the `pcap.filters.AbstractCounterFilter` can be extended to keep track of packet loss, packet order and packet duplication.

Two sub-classes are implemented that define an 8-bit counter (`pcap.filters.CounterFilter8`) and 16-bits counter (`pcap.filters.CounterFilter16`).

These Filters internally rely on a FIFO to detect mis-ordered and duplicate packets, based on their counter value. Depending on the network infrastructure, the default (100 packets) might not be enough and mis-ordered packets arriving too late could be counted as (many!) packets lost, as in the following sequence:

`1 | 2 | 3 | *5* | 6 | 7 | 8 | *4* | 9`

Packet #4 is 4 positions late. If the FIFO size is less than 3 and the counter is 8-bits, a total of 256 lost packets will be detected for the sequence:

* 1 lost from 3 to 5 (packet #4 missing)
* 251 losts from 8 to 4 (packets #9, 10, ...,254, 255, 0, 1, 2, 3 missing)
* 4 losts from 4 to 9 (packets #5 to 8 missing)

Option `-Dreordupl=<FIFO size>` can be used to customize the size of the FIFO and get more accurate results, as in that case, there is no packet loss but a 4-positions reordering.