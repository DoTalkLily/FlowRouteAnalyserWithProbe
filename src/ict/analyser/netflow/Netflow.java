package ict.analyser.netflow;

import ict.analyser.tools.IPTranslator;
import ict.analyser.tools.Utils;

/*
 V5 Flow 结构     gengxin V9

 *-------*-----------*----------------------------------------------------------*
 | Bytes | Contents  | Description                                              |
 *-------*-----------*----------------------------------------------------------*
 | 0-3   | srcaddr   | Source IP address                                        |
 *-------*-----------*----------------------------------------------------------*
 | 4-7   | dstaddr   | Destination IP address                                   |
 *-------*-----------*----------------------------------------------------------*
 | 8-11  | nexthop   | IP address of next hop router                            |
 *-------*-----------*----------------------------------------------------------*
 | 12-13 | input     | Interface index (ifindex) of input interface             |
 *-------*-----------*----------------------------------------------------------*
 | 14-15 | output    | Interface index (ifindex) of output interface            |
 *-------*-----------*----------------------------------------------------------*
 | 16-19 | dPkts     | Packets in the flow                                      |
 *-------*-----------*----------------------------------------------------------*
 | 20-23 | dOctets   | Total number of Layer 3 bytes in the packets of the flow |
 *-------*-----------*----------------------------------------------------------*
 | 24-27 | First     | SysUptime at start of flow                               |
 *-------*-----------*----------------------------------------------------------*
 | 28-31 | Last      | SysUptime at the time the last packet of the flow was    |
 |       |           | received                                                 |
 *-------*-----------*----------------------------------------------------------*
 | 32-33 | srcport   | TCP/UDP source port number or equivalent                 |
 *-------*-----------*----------------------------------------------------------*
 | 34-35 | dstport   | TCP/UDP destination port number or equivalent            |
 *-------*-----------*----------------------------------------------------------*
 | 36    | pad1      | Unused (zero) bytes                                      |
 *-------*-----------*----------------------------------------------------------*
 | 37    | tcp_flags | Cumulative OR of TCP flags                               |
 *-------*-----------*----------------------------------------------------------*
 | 38    | prot      | IP protocol type (for example, TCP = 6; UDP = 17)        |
 *-------*-----------*----------------------------------------------------------*
 | 39    | tos       | IP type of service (ToS)                                 |
 *-------*-----------*----------------------------------------------------------*
 | 40-41 | src_as    | Autonomous system number of the source, either origin or |
 |       |           | peer                                                     |
 *-------*-----------*----------------------------------------------------------*
 | 42-43 | dst_as    | Autonomous system number of the destination, either      |
 |       |           | origin or peer                                           |
 *-------*-----------*----------------------------------------------------------*
 | 44    | src_mask  | Source address prefix mask bits                          |
 *-------*-----------*----------------------------------------------------------*
 | 45    | dst_mask  | Destination address prefix mask bits                     |
 *-------*-----------*----------------------------------------------------------*
 | 46-47 | pad2      | Unused (zero) bytes                                      |
 *-------*-----------*----------------------------------------------------------*

 */

public class Netflow {

	long routerIP = 0;
	int version = 0;
	long unix_secs = 0;
	long srcAddr = 0;
	long dstAddr = 0;
	long nexthop = 0;
	long srcPrefix = 0;
	long dstPrefix = 0;
	int input = -1;
	int output = -1;
	long dPkts = 0;
	long dOctets = 0;
	long first = 0;
	long last = 0;
	int srcPort = -1;
	int dstPort = -1;
	
	short tcpFlags = 0;
	short proc = -1;
	short tos = 0;
	
	int srcAs = -1;
	int dstAs = -1;
	byte srcMask = 0;
	byte dstMask = 0;
	byte protocol = 0;// === 0C 

	public Netflow(byte[] buf) {
		this.routerIP = Utils.byte2long(buf, 0, 4);
		this.version = (int) Utils.byte2long(buf, 4, 4);
		this.unix_secs = Utils.byte2long(buf, 8, 4);
		this.srcAddr = Utils.byte2long(buf, 12, 4);
		this.dstAddr = Utils.byte2long(buf, 16, 4);
		this.nexthop = Utils.byte2long(buf, 20, 4);
		this.input = Utils.byte2int(buf, 24);
		this.output = Utils.byte2int(buf, 26);
		this.dPkts = Utils.byte2long(buf, 28, 4);
		this.dOctets = Utils.byte2long(buf, 32, 4);
		this.first = Utils.byte2long(buf, 36, 4);
		this.last = Utils.byte2long(buf, 40, 4);
		this.srcPort = Utils.byte2int(buf, 44);
		this.dstPort = Utils.byte2int(buf, 46);
		this.tcpFlags = Utils.byte2short(buf, 48);
		this.proc = Utils.byte2short(buf, 50);
		this.tos = Utils.byte2short(buf, 52);
		this.srcMask = buf[54];
		this.dstMask = buf[55];
		this.srcAs =(int) Utils.byte2long(buf, 56, 4);
		this.dstAs = (int) Utils.byte2long(buf, 60, 4);
		
        		
		this.dOctets *= 1000;
//		srctemp = new byte[4];
//		srctemp[0] = buf[56];
//		srctemp[1] = buf[57];
//		srctemp[2] = buf[58];
//		srctemp[3] = buf[59];
//		temp = new byte[4];
//		temp[0] = buf[60];
//		temp[1] = buf[61];
//		temp[2] = buf[62];
//		temp[3] = buf[63];
		
		
		this.srcPrefix = IPTranslator.calLongPrefix(this.srcAddr, this.srcMask);
		this.dstPrefix = IPTranslator.calLongPrefix(this.dstAddr, this.dstMask);

		if (this.dstPort == 21 || this.dstPort == 23 || this.dstPort == 80) {// 只识别ftp
			// telnet和http
			this.protocol = ((Integer) this.dstPort).byteValue();
		}

		if (this.dPkts + this.dOctets <= 0) {
			System.err.println("dPkts and dOctets is illegal");
		}

	}

	//add
//	private byte[] temp ;
//	private byte[] srctemp;
	/**
	 * @return Returns the routerIP.
	 */
	public long getRouterIP() {
		return routerIP;
	}

	/**
	 * @return Returns the version.
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * @return Returns the unix_secs.
	 */
	public long getUnix_secs() {
		return unix_secs;
	}

	/**
	 * @return Returns the srcAddr.
	 */
	public long getSrcAddr() {
		return srcAddr;
	}

	/**
	 * @return Returns the dstAddr.
	 */
	public long getDstAddr() {
		return dstAddr;
	}

	/**
	 * @return Returns the nexthop.
	 */
	public long getNexthop() {
		return nexthop;
	}

	/**
	 * @return Returns the srcPrefix.
	 */
	public long getSrcPrefix() {
		return srcPrefix;
	}

	/**
	 * @return Returns the dstPrefix.
	 */
	public long getDstPrefix() {
		return dstPrefix;
	}

	/**
	 * @return Returns the input.
	 */
	public int getInput() {
		return input;
	}

	/**
	 * @return Returns the output.
	 */
	public int getOutput() {
		return output;
	}

	/**
	 * @return Returns the dPkts.
	 */
	public long getdPkts() {
		return dPkts;
	}

	/**
	 * @return Returns the dOctets.
	 */
	public long getdOctets() {
		return dOctets;
	}

	/**
	 * @return Returns the first.
	 */
	public long getFirst() {
		return first;
	}

	/**
	 * @return Returns the last.
	 */
	public long getLast() {
		return last;
	}

	/**
	 * @return Returns the srcPort.
	 */
	public int getSrcPort() {
		return srcPort;
	}

	/**
	 * @return Returns the dstPort.
	 */
	public int getDstPort() {
		return dstPort;
	}

	/**
	 * @return Returns the tcpFlags.
	 */
	public short getTcpFlags() {
		return tcpFlags;
	}

	/**
	 * @return Returns the proc.
	 */
	public short getProc() {
		return proc;
	}

	/**
	 * @return Returns the tos.
	 */
	public short getTos() {
		return tos;
	}

	/**
	 * @return Returns the srcAs.
	 */
	public int getSrcAs() {
		return srcAs;
	}

	/**
	 * @return Returns the dstAs.
	 */
	public int getDstAs() {
		return dstAs;
	}

	/**
	 * @return Returns the srcMask.
	 */
	public byte getSrcMask() {
		return srcMask;
	}

	/**
	 * @return Returns the dstMask.
	 */
	public byte getDstMask() {
		return dstMask;
	}

	/**
	 * @return Returns the protocol.
	 */
	public byte getProtocol() {
		return protocol;
	}

	/**
	 * 
	 *
	 */
	public void getDetail() {

		System.out.println(" flow detail  " + "router ip:"
				+ IPTranslator.calLongToIp(routerIP) + " version:" + version
				+ "  unix_sec:" + unix_secs + "  src ip"
				+ IPTranslator.calLongToIp(srcAddr) + "  dst ip"
				+ IPTranslator.calLongToIp(dstAddr) + "  nexthop ip"
				+ IPTranslator.calLongToIp(nexthop) + "  packets:" + dPkts
				+ " bytes:" + dOctets + "  first:" + first + "  last:" + last
				+ "  srcport:" + srcPort + "  dstport:" + dstPort + " proc:"
				+ proc +"  tos:"+this.tos+ "  srcAS:" + srcAs + "  dstAS:" + dstAs + "   input:"+this.input+"   output:"+this.output+"    tcpflags:"+this.tcpFlags+"  srcmask:"+this.srcMask+"    dstmask:"+this.dstMask )  ;
	}
}
