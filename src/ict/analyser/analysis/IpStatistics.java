/*
 * Filename: IpStatistics.java
 * Copyright: ICT (c) 2013-3-5
 * Description: 
 * Author: 25hours
 */
package ict.analyser.analysis;

import ict.analyser.netflow.Netflow;
import ict.analyser.statistics.StatisticItem;

import java.util.ArrayList;
import java.util.HashMap;

/**
 * 
 * 这里暂时只在ospf网络统计时才用到这个类，因为ospf可以根据netflow中的as号区分四种类型流量，而isis需要根据前缀找到对应的路由器，
 * 再判断对应流量，因此isis统计将来分1类和2类是需加载IsisAnalyser中，chuyang只有2类网络，因此，认为所有流都是internal的
 * 
 * @author 25hours
 * @version 1.0, 2013-3-5
 */
public class IpStatistics implements Runnable {

	private static int as = -1;// 当前拓扑的as号

	private ArrayList<Long> neighborAsIp = null;

	private ArrayList<Netflow> allFlows = null;// 当前年周期全部流量的引用

	private HashMap<Long, StatisticItem> allItems = null;// 保存分析结果的映射

	public IpStatistics() {
		allItems = new HashMap<Long, StatisticItem>();
	}

	@Override
	public void run() {
		startWorking();
	}

	public void setAS(int asNum) {
		as = asNum;
	}

	public void setFlows(ArrayList<Netflow> flows) {
		if (flows != null) {
			this.allFlows = flows;
		}
	}

	public void setNeighborAsIps(ArrayList<Long> ips) {
		this.neighborAsIp = ips;
	}

	public void startWorking() {
		if (as >= 0) {
			ospfNetwork();
		} else {
			isisNetwork();
		}
		// if (this.allItems.size() != 0) {
		//
		// }
	}

	private void isisNetwork() {
		int size = this.allFlows.size();

		if (size == 0) {
			return;
		}

		Netflow netflow = null;// 标记一条流
		// 开始遍历流，统计在线时长，流量等信息
		for (int i = 0; i < size; i++) {
			netflow = this.allFlows.get(i);// 取得一条流
			updateStatics(netflow, 1);
		}
	}

	private void ospfNetwork() {
		int size = this.allFlows.size();

		if (size == 0) {
			return;
		}

		int srcAS = 0, dstAS = 0;// 标记源和目的as号
		Netflow netflow = null;// 标记一条流
		// 开始遍历流，统计在线时长，流量等信息
		for (int i = 0; i < size; i++) {
			netflow = this.allFlows.get(i);// 取得一条流
			srcAS = netflow.getSrcAs();// 源as号
			dstAS = netflow.getDstAs();// 目的as号

			if ((srcAS == 0 && dstAS == 0) || (srcAS == as && dstAS == as)) {// 如果源和目的设备所在的as号和当前as号相同，是域内flow

				if (this.neighborAsIp != null) {
					if (this.neighborAsIp.contains(netflow.getSrcAddr())) {
						updateStatics(netflow, 2);
					} else if (this.neighborAsIp.contains(netflow.getDstAddr())) {
						updateStatics(netflow, 3);
					}
				}

				updateStatics(netflow, 1);

			} else if ((srcAS != as && dstAS == as)
					|| (srcAS != 0 && dstAS == 0)) { // inbound

				updateStatics(netflow, 2);

			} else if ((srcAS == as && dstAS != as)
					|| (srcAS == 0 && dstAS != 0)) {// outbound

				updateStatics(netflow, 3);
			}
			// } else {// transit
			//
			// // updateStatics(netflow, 4);
			// }
		}
	}

	private void updateStatics(Netflow flow, int direction) {
		if (flow == null) {
			return;
		}

		if (direction == 1 || direction == 3) {// internal & outbound
			update(flow, true);
		}

		if (direction == 1 || direction == 2) {// internal & inbound
			update(flow, false);
		}
	}

	private void update(Netflow flow, boolean isSrc) {

		StatisticItem item = null;// 临时变量

		long bytes = flow.getdOctets();
		long online = flow.getLast() - flow.getFirst();
		long ip = isSrc ? flow.getSrcAddr() : flow.getDstAddr();// 20130531
		long prefix = isSrc ? flow.getSrcPrefix() : flow.getDstPrefix();

		if (ip != 0) {
			item = this.allItems.get(ip);

			if (item == null) {
				item = new StatisticItem();
				item.setIp(ip);
				item.setPrefix(prefix);
				item.setOnline((int) online);

				if (isSrc) { // 20130531
					item.addOutFlow(bytes, flow.getDstPort());
				} else {
					item.addInFlow(bytes, flow.getDstPort());
				}

				item.setTimes(flow.getFirst(), flow.getLast());
				this.allItems.put(ip, item);
			} else {
				// 统计在线时长
				item.setTimes(flow.getFirst(), flow.getLast());// 这里实际是把所有时间段都保存，并按照每段的first大小排序
				// 在线时长统计完毕

				// 统计ip对应流量
				if (isSrc) {
					item.addOutFlow(bytes, flow.getDstPort());// 将出流量叠加
				} else {
					item.addInFlow(bytes, flow.getDstPort());
				}
				// ip对应流量统计完毕
			}
		}
	}

	/**
	 * 清空分析结果数据
	 * 
	 */
	public void clearStatistics() {
		this.allItems.clear();
	}

	/**
	 * @return Returns the allItems.
	 */
	public HashMap<Long, StatisticItem> getAllItems() {
		return allItems;
	}

}
