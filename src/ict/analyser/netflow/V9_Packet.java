/**
 *
 */
package ict.analyser.netflow;

import ict.analyser.collector.Params;
import ict.analyser.tools.IPTranslator;
import ict.analyser.tools.Utils;
import ict.analyser.tools.Variation;

import java.util.ArrayList;

/*

 V9 Flow Packet 

 *-------*--------------- *------------------------------------------------------*
 | Bytes | Contents       | Description                                          |
 *-------*--------------- *------------------------------------------------------*
 | 0-1   | version        | NetFlow export format version number                 |
 *-------*--------------- *------------------------------------------------------*
 | 2-3   | count          | Number of flows exported in this packet (1-30)       |
 *-------*--------------- *------------------------------------------------------*
 | 4-7   | System Uptime  | Current time in milliseconds since the export device |
 |       |                | booted                                               |
 *-------*--------------- *------------------------------------------------------*
 | 8-11  | UNIX Seconds   | Current count of seconds since 0000 UTC 1970         |
 *-------*--------------- *------------------------------------------------------*
 | 12-15 |Package Sequence| Sequence counter of total flows seen                 |
 *-------*--------------- *------------------------------------------------------*
 | 16-19 | Source ID      | Type of flow-switching engine                        |
 *-------*--------------- *------------------------------------------------------*
 */

public class V9_Packet {
	private long count;
	private long routerIP;
	private long sys_uptime, unix_secs, packageSequence;
	private long sourceId;
	private ArrayList<Netflow> normalFlows = null;
	public static final int V9_Header_Size = 20;

	/**
	 * 
	 * 
	 * @param routerIp
	 * @param buf
	 * @param len
	 * @throws DoneException
	 */
	public V9_Packet(long routerIp, byte[] buf, int len) {

		if (len < V9_Header_Size) {
			System.err.println("    * incomplete header *");
			return;
		}

		this.routerIP = routerIp;
		this.count = Utils.to_number(buf, 2, 2);
		this.sys_uptime = Utils.to_number(buf, 4, 4);
		this.unix_secs = Utils.to_number(buf, 8, 4);
		this.packageSequence = Utils.to_number(buf, 12, 4);
		this.sourceId = Utils.to_number(buf, 16, 4);
		this.normalFlows = new ArrayList<Netflow>();
		Variation vrat = Variation.getInstance();
		vrat.setVary(this.routerIP, this.sys_uptime);
		long flowsetLength = 0l;

		for (int flowsetCounter = 0, packetOffset = V9_Header_Size; flowsetCounter < this.count
				&& packetOffset < len; flowsetCounter++, packetOffset += flowsetLength) {
			long flowsetId = Utils.to_number(buf, packetOffset, 2);
			flowsetLength = Utils.to_number(buf, packetOffset + 2, 2);

			if (flowsetLength == 0) {
				System.err.println("There is a flowset len=0.");
				return;
			}

			String ipStr = IPTranslator.calLongToIp(this.routerIP);

			if (flowsetId == 0) {

				int thisTemplateOffset = packetOffset + 4;
				do {
					long templateId = Utils.to_number(buf, thisTemplateOffset,
							2);
					long fieldCount = Utils.to_number(buf,
							thisTemplateOffset + 2, 2);
					if (TemplateManager.getTemplateManager().getTemplate(ipStr,
							(int) templateId) == null
							|| Params.v9TemplateOverwrite) {
						TemplateManager.getTemplateManager().acceptTemplate(
								ipStr, buf, thisTemplateOffset);
					}

					thisTemplateOffset += fieldCount * 4 + 4;

				} while (thisTemplateOffset - packetOffset < flowsetLength);

			} else if (flowsetId > 255) {
				Template tOfData = TemplateManager.getTemplateManager()
						.getTemplate(ipStr, (int) flowsetId); // flowsetId==templateId

				if (tOfData != null) {

					int dataRecordLen = tOfData.getTypeOffset(-1);

					for (int p = packetOffset + 4; (p - packetOffset + dataRecordLen) < flowsetLength; p += dataRecordLen) {
						Netflow flow = new Netflow(routerIp, buf, p, tOfData,
								this.unix_secs);
						normalFlows.add(flow);
					}

				} else { // options packet, should refer to option template, not
					continue;
				}

			} else if (flowsetId == 1) { // options flowset
				continue;
			}
		}
	}

	/**
	 * @return Returns the count.
	 */
	public long getCount() {
		return count;
	}

	/**
	 * @return Returns the routerIP.
	 */
	public long getRouterIP() {
		return routerIP;
	}

	/**
	 * @return Returns the sys_uptime.
	 */
	public long getSys_uptime() {
		return sys_uptime;
	}

	/**
	 * @return Returns the unix_secs.
	 */
	public long getUnix_secs() {
		return unix_secs;
	}

	/**
	 * @return Returns the packageSequence.
	 */
	public long getPackageSequence() {
		return packageSequence;
	}

	/**
	 * @return Returns the sourceId.
	 */
	public long getSourceId() {
		return sourceId;
	}

	/**
	 * @return Returns the normalFlows.
	 */
	public ArrayList<Netflow> getNormalFlows() {
		return normalFlows;
	}

}
