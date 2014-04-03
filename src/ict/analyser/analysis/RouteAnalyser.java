/*
 * Filename: RouteAnalyser.java
 * Copyright: ICT (c) 2012-11-22
 * Description: 
 * Author: 25hours
 */
package ict.analyser.analysis;

import ict.analyser.common.Constant;
import ict.analyser.database.DBOperator;
import ict.analyser.flow.Path;
import ict.analyser.flow.TrafficLink;
import ict.analyser.isistopo.IsisTopo;
import ict.analyser.netflow.Netflow;
import ict.analyser.ospftopo.OspfTopo;
import ict.analyser.statistics.StatisticItem;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-11-22
 */
public class RouteAnalyser {
	private long pid = 0;
	private OspfTopo ospfTopo = null;
	private IsisTopo isisTopo = null;
	private ArrayList<OspfAnalyser> ospfAnalysers = null;// 维护一个所有正在运行的分析线程的列表
	private ArrayList<IsisAnalyser> isisAnalysers = null;// 维护一个所有正在运行的分析线程的列表
	private HashMap<String, Long> mapProtocalBytes = null;// 赋值给每个TrafficLink的映射
	private HashMap<Integer, String> mapPortProtocal = null;// 维护一个端口号——协议名字映射
	private HashMap<Integer, TrafficLink> mapLidTlink = null;// linkid——traffic
	private ConcurrentHashMap<String, Path> foundPath = null;// key是源路由器id+“_”+目的路由器id
	private ConcurrentHashMap<Long, StatisticItem> allItems = null;// 保存分析结果的映射

	public RouteAnalyser() {
		this.ospfAnalysers = new ArrayList<OspfAnalyser>();
		this.isisAnalysers = new ArrayList<IsisAnalyser>();
		this.mapLidTlink = new HashMap<Integer, TrafficLink>();
		this.foundPath = new ConcurrentHashMap<String, Path>();
		this.allItems = new ConcurrentHashMap<Long, StatisticItem>();
	}

	public void resetMaterials() {
		this.foundPath.clear();// 这里去掉bug现象是：结果上报了本周起没有的链路。原因：这里没按周期清空，因此链路丢失也一直会保存已找到的路径。
		this.isisAnalysers.clear();
		this.ospfAnalysers.clear();
	}

	/**
	 * 根据上一个周期得到的需要提前计算的源——目的list映射，用新的拓扑提前计算最短路径
	 * 
	 */
	public void ospfPreCalculate() {
		resetMaterials();

		ArrayList<Long> allRouterIds = this.ospfTopo.getAllRouterIds();// 得到全部路由器id列表，供n个线程互斥访问
		int eachSize = allRouterIds.size() / Constant.PRECAL_THREAD_COUNT;// 将条目总数分成若干份，每份条目数

		for (int i = 0; i < Constant.PRECAL_THREAD_COUNT; i++) {
			OspfAnalyser analyser = new OspfAnalyser(this, this.ospfTopo,
					Constant.PRE_CAL, null);// 第二个参数决定是否是提前分析路径
			analyser.setRouterIdsToPrecal(allRouterIds.subList(i * eachSize,
					(i + 1) * eachSize));
			analyser.start();
			ospfAnalysers.add(analyser);// 线程开始运行
		}

		for (int i = 0; i < Constant.PRECAL_THREAD_COUNT; i++) {// 等待全部线程结束
			try {
				ospfAnalysers.get(i).join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	public void isisPreCalculate() {
		resetMaterials();

		ArrayList<Long> allRouterIds = this.isisTopo.getAllRouterIds();// 得到全部路由器id列表，供n个线程互斥访问
		int eachSize = allRouterIds.size() / Constant.PRECAL_THREAD_COUNT;// 将条目总数分成若干份，每份条目数

		for (int i = 0; i < Constant.PRECAL_THREAD_COUNT; i++) {
			IsisAnalyser analyser = new IsisAnalyser(this, this.isisTopo,
					Constant.PRE_CAL, null);// 第二个参数决定是否是提前分析路径
			analyser.setRouterIdsToPrecal(allRouterIds.subList(i * eachSize,
					(i + 1) * eachSize));
			analyser.start();
			isisAnalysers.add(analyser);
		}

		for (int i = 0; i < Constant.PRECAL_THREAD_COUNT; i++) {
			try {
				isisAnalysers.get(i).join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	public void ospfRouteCalculate(long pid, int index,
			ArrayList<Netflow> netflows) {
		this.allItems.clear();
		this.ospfAnalysers.clear();// bug修正：之前在topo数据没变化的时候没有清理ospfanalyser
		// 和isisanalyser列表，导致单个线程结束后唤醒的是就线程对象，因此不能唤醒。

		if (netflows == null || netflows.size() == 0) {
			return;
		}

		if (pid % 10000 == 0 || index == 1) {
			DBOperator.createTable(pid);
		}

		this.pid = pid;
		OspfAnalyser analyser = null;

		if (netflows.size() < Constant.A_FEW) {
			analyser = new OspfAnalyser(this, this.ospfTopo,
					Constant.ROUTE_CAL, netflows);
			analyser.start();
			this.ospfAnalysers.add(analyser);
		} else {
			int eachSize = netflows.size() / Constant.FLOWCAL_THREAD_COUNT;// 将条目总数分成若干份，每份条目数

			for (int i = 0; i < Constant.FLOWCAL_THREAD_COUNT; i++) {// 为每份netflow分别起一个RouteAnalysis线程
				analyser = new OspfAnalyser(this, this.ospfTopo,
						Constant.ROUTE_CAL, netflows.subList(i * eachSize,
								(i + 1) * eachSize));
				analyser.start();
				this.ospfAnalysers.add(analyser);// 加入列表集中管理
			}
		}

		for (int i = 0, len = this.ospfAnalysers.size(); i < len; i++) {
			analyser = this.ospfAnalysers.get(i);

			try {
				analyser.join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}

			gatherLidTraffic(analyser.getMapLidTraffic());
		}
		netflows.clear();
	}

	public void isisRouteCalculate(long pid, int index,
			ArrayList<Netflow> netflows) {
		this.allItems.clear();
		this.isisAnalysers.clear();

		if (netflows == null || netflows.size() == 0) {
			return;
		}

		if (pid % 10000 == 0 || index == 1) {
			DBOperator.createTable(pid);
		}

		this.pid = pid;
		IsisAnalyser analyser = null;// isis路径分析类

		if (netflows.size() < Constant.A_FEW) {// 如果流大小小于一定数量（待定），只分给一个analyser计算
			analyser = new IsisAnalyser(this, this.isisTopo,
					Constant.ROUTE_CAL, netflows);
			analyser.start();// 线程开始运行
			isisAnalysers.add(analyser);
		} else {
			int eachSize = netflows.size() / Constant.FLOWCAL_THREAD_COUNT;// 将条目总数分成若干份，每份条目数

			for (int i = 0; i < Constant.FLOWCAL_THREAD_COUNT; i++) {// 为每份netflow分别起一个RouteAnalysis线程
				analyser = new IsisAnalyser(this, this.isisTopo,
						Constant.ROUTE_CAL, netflows.subList(i * eachSize,
								(i + 1) * eachSize));
				analyser.start();
				this.isisAnalysers.add(analyser);// 加入列表集中管理

			}
		}

		for (int i = 0, len = this.isisAnalysers.size(); i < len; i++) {
			analyser = this.isisAnalysers.get(i);

			try {
				analyser.join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}

			gatherLidTraffic(analyser.getMapLidTraffic());
		}
		netflows.clear();
	}

	/**
	 * 各个计算线程向主线程的foundPath缓存中插入数据
	 * 
	 * @param ids
	 *            源id+“_”+目的id
	 * @param path
	 *            源到目的路径
	 */
	public void insertFoundPath(String ids, Path path) {
		this.foundPath.put(ids, path);
	}

	/**
	 * 根据源id+“_”+目的id字符串找到缓存的path，如果没有返回空
	 * 
	 * @param ids
	 *            源id+“_”+目的id字符串
	 * @return 缓存的path，如果没有返回空
	 */
	public Path getPathByIds(String ids) {
		return this.foundPath.get(ids);
	}

	/**
	 * 一次向foundPath插入多于一条的记录
	 * 
	 * @param paths
	 */
	public void insertMorePath(HashMap<String, Path> paths) {
		this.foundPath.putAll(paths);
	}

	/**
	 * 从单个analyser得到的映射汇总到主分析线程的映射，经过测试，两个10000条的map合并大约20-40ms
	 * 
	 * @param linkIdByte
	 */
	private void gatherLidTraffic(HashMap<Integer, TrafficLink> trafficToAdd) {
		if (trafficToAdd == null) {
			return; // 如果为空，返回
		}

		Iterator<Entry<Integer, TrafficLink>> iter = trafficToAdd.entrySet()
				.iterator();
		Map.Entry<Integer, TrafficLink> entry = null;
		int id = 0;
		TrafficLink toAdd = null, inArr = null;

		while (iter.hasNext()) {
			entry = iter.next();
			id = entry.getKey();
			toAdd = entry.getValue();

			if (id != 0 && toAdd != null && this.mapLidTlink.containsKey(id)) {
				inArr = this.mapLidTlink.get(id);

				if (inArr == null) {
					this.mapLidTlink.put(id, toAdd);
				} else {
					inArr.combineTraffic(toAdd);// 有则累加
				}
			}
		}
	}

	public void updateStatics(Netflow flow, int direction) {
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
		// long online = flow.getLast() - flow.getFirst();
		long ip = isSrc ? flow.getSrcAddr() : flow.getDstAddr();// 20130531
		long prefix = isSrc ? flow.getSrcPrefix() : flow.getDstPrefix();

		if (ip != 0) {
			item = this.allItems.get(ip);

			if (item == null) {
				item = new StatisticItem();
				item.setIp(ip);
				item.setPrefix(prefix);

				if (isSrc) { // 20130531
					item.addOutFlow(bytes, flow.getDstPort());
				} else {
					item.addInFlow(bytes, flow.getDstPort());
				}

				// item.setTimes(flow.getFirst(), flow.getLast());
				this.allItems.put(ip, item);
			} else {
				// 统计在线时长
				// item.setTimes(flow.getFirst(), flow.getLast());//
				// 这里实际是把所有时间段都保存，并按照每段的first大小排序
				// 在线时长统计完毕

				// 统计ip对应流量
				if (isSrc) {
					item.addOutFlow(bytes, flow.getDstPort());// 将出流量叠加
				} else {
					item.addInFlow(bytes, flow.getDstPort());
				}
				// ip对应流量统计完毕
			}
			item.setOnline();
		}
	}

	/**
	 * @return Returns the mapProtocalBytes.
	 */
	@SuppressWarnings("unchecked")
	public HashMap<String, Long> getMapProtocalBytes() {
		return (HashMap<String, Long>) mapProtocalBytes.clone();
	}

	public void setTopo(OspfTopo topo) {
		if (topo == null) {
			return;
		}

		this.ospfTopo = topo;
		setMapLidTlink(topo.getLinkIds());
	}

	public void setTopo(IsisTopo topo) {
		this.isisTopo = topo;
	}

	/**
	 * @return Returns the period.
	 */
	public long getPeriod() {
		return pid;
	}

	/**
	 * @return Returns the mapLidTlink.
	 */
	public String getProtocalByPort(int port) {
		return mapPortProtocal.get(port);
	}

	/**
	 * @return Returns the mapPortProtocal.
	 */
	public HashMap<Integer, String> getMapPortProtocal() {
		return mapPortProtocal;
	}

	/**
	 * @param mapPortProtocal
	 *            The mapPortProtocal to set.
	 */
	public void setMapPortProtocal(HashMap<Integer, String> mapPortProtocal) {
		this.mapPortProtocal = mapPortProtocal;

		Entry<Integer, String> entry;
		Iterator<Entry<Integer, String>> iterator = mapPortProtocal.entrySet()
				.iterator();

		if (this.mapProtocalBytes == null) {
			this.mapProtocalBytes = new HashMap<String, Long>();
		} else {
			this.mapProtocalBytes.clear();
		}

		while (iterator.hasNext()) {
			entry = iterator.next();
			this.mapProtocalBytes.put(entry.getValue(), 0l);
		}
		this.mapProtocalBytes.put("other", 0l);// 其他协议类型
	}

	/**
	 * 用当前周期的拓扑的所有link id 初始化当前周期要分析的所有link id——traffic link 映射
	 * 
	 * @param mapLidTlink
	 *            The mapLidTlink to set.
	 */
	public void setMapLidTlink(ArrayList<Integer> linkids) {
		if (linkids == null) {
			return;
		}

		int size = linkids.size();

		for (int i = 0; i < size; i++) {
			this.mapLidTlink.put(linkids.get(i), null);
		}
	}

	public HashMap<Integer, TrafficLink> getMapLidTlink() {
		return this.mapLidTlink;
	}

	/**
	 * @return Returns the allItems.
	 */
	public ConcurrentHashMap<Long, StatisticItem> getAllItems() {
		return allItems;
	}
}
