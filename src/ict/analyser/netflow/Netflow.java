package ict.analyser.netflow;

import ict.analyser.tools.IPTranslator;
import ict.analyser.tools.Utils;
import ict.analyser.tools.Variation;

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

public class Netflow implements Cloneable {
	long routerIP = 0;
	long srcRouter = 0;// 源路由器id
	long dstRouter = 0;// 目的路由器id
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
	byte tcpFlags = 0;
	byte proc = -1;
	byte tos = 0;
	int srcAs = -1;
	int dstAs = -1;
	byte srcMask = 0;
	byte dstMask = 0;

	public Netflow(long routerIp, byte[] buf, int off, long unix_secs) {
		this.version = 5;
		this.routerIP = routerIp;
		this.unix_secs = unix_secs;

		this.srcAddr = Utils.byte2long(buf, off, 4);
		this.dstAddr = Utils.byte2long(buf, off + 4, 4);
		this.nexthop = Utils.byte2long(buf, off + 8, 4);
		this.input = Utils.byte2int(buf, off + 12);
		this.output = Utils.byte2int(buf, off + 14);
		this.dPkts = Utils.byte2long(buf, off + 16, 4);
		this.dOctets = Utils.byte2long(buf, off + 20, 4);
		this.first = Utils.byte2long(buf, off + 24, 4);
		this.last = Utils.byte2long(buf, off + 28, 4);
		this.srcPort = Utils.byte2int(buf, off + 32);
		this.dstPort = Utils.byte2int(buf, off + 34);
		this.tcpFlags = buf[off + 37];
		this.proc = buf[off + 38];
		this.tos = buf[off + 39];
		this.srcAs = Utils.byte2int(buf, off + 40);
		this.dstAs = Utils.byte2int(buf, off + 42);
		this.srcMask = buf[off + 44];
		this.dstMask = buf[off + 45];

		this.srcPrefix = IPTranslator.calLongPrefix(this.srcAddr, this.srcMask);
		this.dstPrefix = IPTranslator.calLongPrefix(this.dstAddr, this.dstMask);
	}

	public static final int V9_Header_Size = 20;

	public Netflow(long routerIp, final byte[] buf, int off, Template template,
			long unix_secs) {
		this.version = 9;
		this.unix_secs = unix_secs;
		this.routerIP = routerIp;

		if (buf.length < template.getTypeOffset(-1)) {
			System.err.println("invalid packets!");
			return;
		}

		int offset = template.getTypeOffset(FieldDefinition.IPV4_SRC_ADDR);
		int length = template.getTypeLen(FieldDefinition.IPV4_SRC_ADDR);

		if (offset >= 0 && length > 0) {
			this.srcAddr = Utils.to_number(buf, off + offset, length);
		}

		offset = template.getTypeOffset(FieldDefinition.IPV4_DST_ADDR);
		length = template.getTypeLen(FieldDefinition.IPV4_DST_ADDR);

		if (offset >= 0 && length > 0) {
			this.dstAddr = Utils.to_number(buf, off + offset, length);
		}

		offset = template.getTypeOffset(FieldDefinition.IPV4_NEXT_HOP);
		length = template.getTypeLen(FieldDefinition.IPV4_NEXT_HOP);

		if (offset >= 0 && length > 0) {
			this.nexthop = Utils.to_number(buf, off + offset, length);
		}

		offset = template.getTypeOffset(FieldDefinition.INPUT_SNMP);
		length = template.getTypeLen(FieldDefinition.INPUT_SNMP);

		if (offset >= 0 && length > 0) {
			this.input = (int) Utils.to_number(buf, off + offset, length);
		}

		offset = template.getTypeOffset(FieldDefinition.OUTPUT_SNMP);
		length = template.getTypeLen(FieldDefinition.OUTPUT_SNMP);

		if (offset >= 0 && length > 0) {
			this.output = (int) Utils.to_number(buf, off + offset, length);
		}

		offset = template.getTypeOffset(FieldDefinition.InPKTS_32);
		length = template.getTypeLen(FieldDefinition.InPKTS_32);

		if (offset >= 0 && length > 0) {
			this.dPkts = Utils.to_number(buf, off + offset, length)
					* template.getSamplingRate();
		}

		offset = template.getTypeOffset(FieldDefinition.InBYTES_32);
		length = template.getTypeLen(FieldDefinition.InBYTES_32);

		if (offset >= 0 && length > 0) {
			this.dOctets = Utils.to_number(buf, off + offset, length)
					* template.getSamplingRate();
		}

		offset = template.getTypeOffset(FieldDefinition.FIRST_SWITCHED);
		length = template.getTypeLen(FieldDefinition.FIRST_SWITCHED);

		if (offset >= 0 && length > 0) {
			this.first = Utils.to_number(buf, off + offset, length);

			if (!Variation.getInstance().judgeVary(first)) {
				System.err.println("Time mismatch!");
			}
		}

		offset = template.getTypeOffset(FieldDefinition.LAST_SWITCHED);
		length = template.getTypeLen(FieldDefinition.LAST_SWITCHED);

		if (offset >= 0 && length > 0) {
			try {
				this.last = Utils.to_number(buf, off + offset, length);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		offset = template.getTypeOffset(FieldDefinition.L4_SRC_PORT);
		length = template.getTypeLen(FieldDefinition.L4_SRC_PORT);

		if (offset >= 0 && length > 0) {
			this.srcPort = (int) Utils.to_number(buf, off + offset, length);
		}

		offset = template.getTypeOffset(FieldDefinition.L4_DST_PORT);
		length = template.getTypeLen(FieldDefinition.L4_DST_PORT);

		if (offset >= 0 && length > 0) {
			this.dstPort = (int) Utils.to_number(buf, off + offset, length);
		}

		offset = template.getTypeOffset(FieldDefinition.TCP_FLAGS);
		length = template.getTypeLen(FieldDefinition.TCP_FLAGS);

		if (offset >= 0 && length > 0) {
			this.tcpFlags = buf[off + offset];
		}

		offset = template.getTypeOffset(FieldDefinition.PROT);
		length = template.getTypeLen(FieldDefinition.PROT);

		if (offset >= 0 && length > 0) {
			this.proc = buf[off + offset];
		}

		offset = template.getTypeOffset(FieldDefinition.SRC_TOS);
		length = template.getTypeLen(FieldDefinition.SRC_TOS);

		if (offset >= 0 && length > 0) {
			this.tos = buf[off + offset];
		}

		offset = template.getTypeOffset(FieldDefinition.SRC_AS);
		length = template.getTypeLen(FieldDefinition.SRC_AS);

		if (offset >= 0 && length > 0) {
			this.srcAs = (int) Utils.to_number(buf, off + offset, length);
		}

		offset = template.getTypeOffset(FieldDefinition.DST_AS);
		length = template.getTypeLen(FieldDefinition.DST_AS);

		if (offset >= 0 && length > 0) {
			this.dstAs = (int) Utils.to_number(buf, off + offset, length);
		}

		offset = template.getTypeOffset(FieldDefinition.SRC_MASK);
		length = template.getTypeLen(FieldDefinition.SRC_MASK);

		if (offset >= 0 && length > 0) {
			this.srcMask = buf[off + offset];
		}

		offset = template.getTypeOffset(FieldDefinition.DST_MASK);
		length = template.getTypeLen(FieldDefinition.DST_MASK);

		if (offset >= 0 && length > 0) {
			this.dstMask = buf[off + offset];
		}

		if (this.srcAddr != 0 || this.srcMask != 0) {
			this.srcPrefix = IPTranslator.calLongPrefix(this.srcAddr,
					this.srcMask);
			this.dstPrefix = IPTranslator.calLongPrefix(this.dstAddr,
					this.dstMask);
		}

		if (this.dPkts + this.dOctets <= 0) {
			System.err.println("illegal packet num and doctets!");
		}
	}

	public boolean equals(Netflow obj) {
		if ((this.input == obj.input) && (this.srcAddr == obj.srcAddr)
				&& (this.dstAddr == obj.dstAddr) && (this.proc == obj.proc)
				&& (this.srcPort == obj.srcPort)
				&& (this.dstPort == obj.dstPort) && (this.tos == obj.tos)) {
			return true;
		} else {
			return false;
		}
	}

	public String getKey() {
		String key = this.srcAddr + "_" + this.dstAddr + "_" + this.srcPort
				+ "_" + this.dstPort + "_" + this.proc;
		return key;
	}

	@Override
	public Object clone() throws CloneNotSupportedException {
		return super.clone();
	}

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
	 * @return Returns the srcRouter.
	 */
	public long getSrcRouter() {
		return srcRouter;
	}

	/**
	 * @param srcRouter
	 *            The srcRouter to set.
	 */
	public void setSrcRouter(long srcRouter) {
		this.srcRouter = srcRouter;
	}

	/**
	 * @return Returns the dstRouter.
	 */
	public long getDstRouter() {
		return dstRouter;
	}

	/**
	 * @param dstRouter
	 *            The dstRouter to set.
	 */
	public void setDstRouter(long dstRouter) {
		this.dstRouter = dstRouter;
	}

	/**
	 * @param srcAs
	 *            The srcAs to set.
	 */
	public void setSrcAs(int srcAs) {
		this.srcAs = srcAs;
	}

	/**
	 * @param dstAs
	 *            The dstAs to set.
	 */
	public void setDstAs(int dstAs) {
		this.dstAs = dstAs;
	}

	/**
	 * 
	 * 
	 * @param getdOctets
	 */
	public void addOctets(long dOctets) {
		this.dOctets += dOctets;
	}

	/**
	 * 
	 *
	 */
	public void printDetail() {
		System.out.println(" flow detail  " + "router ip:"
				+ IPTranslator.calLongToIp(routerIP) + " src router id:"
				+ IPTranslator.calLongToIp(srcRouter) + "  dst router id:"
				+ IPTranslator.calLongToIp(dstRouter) + " version:" + version
				+ "  unix_sec:" + unix_secs + "  src ip"
				+ IPTranslator.calLongToIp(srcAddr) + "  dst ip"
				+ IPTranslator.calLongToIp(dstAddr) + "  nexthop ip"
				+ IPTranslator.calLongToIp(nexthop) + "  packets:" + dPkts
				+ " bytes:" + dOctets + "  first:" + first + "  last:" + last
				+ "  srcport:" + srcPort + "  dstport:" + dstPort + " proc:"
				+ proc + "  tos:" + this.tos + "  srcAS:" + srcAs + "  dstAS:"
				+ dstAs + "   input:" + this.input + "   output:" + this.output
				+ "    tcpflags:" + this.tcpFlags + "  srcmask:" + this.srcMask
				+ "    dstmask:" + this.dstMask);
	}
}
