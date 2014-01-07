/*
 * Filename: StatisticItem.java
 * Copyright: ICT (c) 2013-3-5
 * Description: 
 * Author: 25hours
 */
package ict.analyser.statistics;

import ict.analyser.analysis.MainProcesser;
import ict.analyser.config.ConfigData;

import java.util.HashMap;

/**
 * 统计ip在线时长和ip对应流量大小以及前缀对应流量大小信息的条目 修改记录：把出入流量 inFlow outFlow 类型改成long 20130515
 * 
 * @author 25hours
 * @version 1.0, 2013-3-5
 */
public class StatisticItem {
	private long ip = 0; // long型表示的ip
	private int online = 0;// ip在一个周期内的在线时长，这里暂定以ms为单位
	private long inFlow = 0; // ip在一个周期内对应的入流量大小，以Byte为单位
	private long prefix = 0; // long型ip所属前缀
	private long outFlow = 0;// // ip在一个周期内对应的出流量大小，以Byte为单位
	// private ArrayList<long[]> times = null;// 用于统计在线时间段
	// private ArrayList<long[]> test = new ArrayList<long[]>();
	private HashMap<String, Long> mapInFlow = null;// 入ip流量细化
	private HashMap<String, Long> mapOutFlow = null;// 出ip流量细化
	private static int INTERVAL = MainProcesser.getInterval();

	public StatisticItem() {
		// times = new ArrayList<long[]>();
		mapInFlow = new HashMap<String, Long>();
		mapOutFlow = new HashMap<String, Long>();
	}

	/**
	 * @return Returns the ip.
	 */
	public long getIp() {
		return ip;
	}

	/**
	 * @param ip
	 *            The ip to set.
	 */
	public void setIp(long ip) {
		this.ip = ip;
	}

	/**
	 * @return Returns the online.
	 */
	public int getOnline() {
		// aggregate();
		// getTotal();

		// if (this.online < 0 || this.online > Integer.MAX_VALUE) {
		// System.out.println("ip online time is out of range!!!!! "
		// + this.online + "  ");
		// for (long[] l : test) {
		// System.out.print(l[0] + ":" + l[1] + ",");
		// }
		//
		// System.out.println();
		// this.online = MAX_ONLINE_TIME;
		// }
		return this.online;
	}

	// public void getTotal() {
	// int size = this.times.size();
	//
	// if (size == 0) {
	// return;
	// }
	//
	// long[] t = this.times.get(0);
	// long total = t[1] - t[0];
	// long oldLast = t[1];
	// long interval = 0;
	//
	// for (int i = 1; i < size; i++) {
	// t = this.times.get(i);
	// interval = t[0] - oldLast;
	//
	// if (interval > 0 && interval < 15 * 1000) {
	// total += t[1] - oldLast;
	// } else if (interval > 15 * 1000) {
	// total += 5 * 1000 + t[1] - t[0];
	// }
	// oldLast = t[1];// 标记last为当前时间段的last
	// }
	// this.online = (int) total;
	// }
	//
	// private void aggregate() {
	// int size = this.times.size();
	//
	// if (size <= 1) {
	// return;
	// }
	//
	// long[] t = this.times.get(0);
	// long oldFirst = t[0], oldLast = t[1];
	// ArrayList<long[]> result = new ArrayList<long[]>();
	//
	// for (int i = 1; i < size; i++) {
	// t = this.times.get(i);
	//
	// if (t[0] >= oldFirst && t[0] <= oldLast) {
	// oldLast = Math.max(oldLast, t[1]);
	// } else {
	// long[] temp = { oldFirst, oldLast };
	// result.add(temp);
	// oldFirst = t[0];
	// oldLast = t[1];
	// }
	// }
	//
	// long[] temp = { oldFirst, oldLast };
	// result.add(temp);
	// this.times = result;
	// }

	// /**
	// *
	// * 比较两个时间段是否有交集
	// *
	// * @param a
	// * 已缓存的时间段
	// * @param b
	// * 待比较的时间段
	// * @return 相交 ——1 内含——2 外含——3 相离——4
	// */
	// public int isIntersect(long[] a, long[] b) {
	//
	// if (b[0] >= a[0] && b[0] <= a[1]) {
	// return b[1] > a[1] ? 1 : 2;
	// } else if (b[0] < a[0]) {
	// if (b[1] < a[0]) {
	// return 4;
	// } else if (b[1] < a[1]) {
	// return 1;
	// } else {// (b[1] > a[1])
	// return 3;
	// }
	// } else {// b[0] > a[1]
	// return 4;
	// }
	// }

	/**
	 * @return Returns the prefix.
	 */
	public long getPrefix() {
		return prefix;
	}

	/**
	 * @param prefix
	 *            The prefix to set.
	 */
	public void setPrefix(long prefix) {
		this.prefix = prefix;
	}

	/**
	 * @return Returns the inFlow.
	 */
	public long getInFlow() {
		return inFlow;
	}

	/**
	 * @param inFlow
	 *            The inFlow to set.
	 */
	public void addInFlow(long bytes, int port) {
		this.inFlow += bytes;
		addFlowDetail(bytes, port, true);
	}

	/**
	 * @return Returns the outFlow.
	 */
	public long getOutFlow() {
		return outFlow;
	}

	/**
	 * @param outFlow
	 *            The outFlow to set.
	 */
	public void addOutFlow(long bytes, int port) {
		this.outFlow += bytes;
		addFlowDetail(bytes, port, false);
	}

	/**
	 * 根据端口号将流量按出业务类别细分
	 * 
	 * @param bytes
	 *            流量大小
	 * @param port
	 *            端口
	 * @param isIn
	 *            是否是入流量 true——是 false——出
	 */
	private void addFlowDetail(long bytes, int port, boolean isIn) {
		addFlowToMap(ConfigData.getProtocalByPort(port), bytes, isIn);// 根据端口号判断协议类型进行相应统计
	}

	private void addFlowToMap(String protocal, long bytes, boolean isIn) {
		if (protocal == null || bytes == 0) {
			return;
		}

		Object o;

		// 入流量叠加
		if (isIn) {
			o = this.mapInFlow.get(protocal);

			if (o == null) {
				this.mapInFlow.put(protocal, bytes);
			} else {
				this.mapInFlow.put(protocal, bytes + (Long) o);
			}
		} else { // 出流量叠加
			o = this.mapOutFlow.get(protocal);

			if (o == null) {
				this.mapOutFlow.put(protocal, bytes);
			} else {
				this.mapOutFlow.put(protocal, bytes + (Long) o);
			}
		}

	}

	public void setOnline() {
		this.online = INTERVAL;
	}

	/**
	 * @return Returns the mapInFlow.
	 */
	public HashMap<String, Long> getMapInFlow() {
		return mapInFlow;
	}

	/**
	 * @param mapInFlow
	 *            The mapInFlow to set.
	 */
	public void setMapInFlow(String pro, long bytes) {
		if (pro != null) {
			this.mapInFlow.put(pro, bytes);
		}
	}

	/**
	 * @return Returns the mapOutFlow.
	 */
	public HashMap<String, Long> getMapOutFlow() {
		return mapOutFlow;
	}

	/**
	 * @param mapOutFlow
	 *            The mapOutFlow to set.
	 */
	public void setMapOutFlow(String pro, long bytes) {
		if (pro != null) {
			this.mapOutFlow.put(pro, bytes);
		}
	}

	// /**
	// * @param times
	// * The times to set.
	// */
	// public void setTimes(long first, long last) {
	//
	// if (first < 0 || last < 0) {
	// return;
	// }
	//
	// int size = this.times.size();
	// long[] t = { first, last };
	// long[] saved = null;
	//
	// if (size == 0) {
	// this.times.add(t);
	// this.test.add(t);
	// return;
	// }
	//
	// int i;
	//
	// for (i = 0; i < size; i++) {
	// saved = this.times.get(i);
	//
	// if (first <= saved[0]) {
	// this.times.add(i, t);
	// this.test.add(t);
	// break;
	// }
	// }
	//
	// if (i == size) {// 如果first大于已经缓存的任意时间段的first，加到数组最后
	// this.times.add(t);
	// this.test.add(t);
	// }
	// }
}
