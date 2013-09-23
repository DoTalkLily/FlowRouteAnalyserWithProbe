/*
 * Filename: RouteAnalyser.java
 * Copyright: ICT (c) 2012-11-22
 * Description: 
 * Author: 25hours
 */
package ict.analyser.analysis;

import ict.analyser.flow.Path;
import ict.analyser.flow.TrafficLink;
import ict.analyser.isistopo.IsisTopo;
import ict.analyser.netflow.Netflow;
import ict.analyser.ospftopo.OspfTopo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Logger;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-11-22
 */
public class RouteAnalyser {
	private long period = 0;
	private int divideCount = 0;
	private static int SINGLE_COUNT = 1000;// 流数量小于singleCount的只需要一个analyser就能执行，待定
	private OspfTopo ospfTopo = null;
	private IsisTopo isisTopo = null;
	private ArrayList<Netflow> netflows = null;// flow接收模块分析并聚合后得到的报文对象列表
	private ArrayList<Long> allRouterIds = null;// 全部路由器id列表
	private HashMap<String, Path> foundPath = null;// key是源路由器id+“_”+目的路由器id
	private ArrayList<OspfAnalyser> ospfAnalysers = null;// 维护一个所有正在运行的分析线程的列表
	private ArrayList<IsisAnalyser> isisAnalysers = null;// 维护一个所有正在运行的分析线程的列表
	private HashMap<String, Long> mapProtocalBytes = null;// 赋值给每个TrafficLink的映射
	private HashMap<Integer, String> mapPortProtocal = null;// 维护一个端口号——协议名字映射
	private HashMap<Integer, TrafficLink> mapLidTlink = null;// linkid——traffic
	private Logger logger = Logger.getLogger(RouteAnalyser.class.getName());// 注册一个logger

	public RouteAnalyser() {
		this.netflows = new ArrayList<Netflow>();
		this.foundPath = new HashMap<String, Path>();
		this.ospfAnalysers = new ArrayList<OspfAnalyser>();
		this.isisAnalysers = new ArrayList<IsisAnalyser>();
		this.mapLidTlink = new HashMap<Integer, TrafficLink>();
	}

	public void resetMaterials() {
		this.foundPath.clear();// 这里去掉bug现象是：结果上报了本周起没有的链路。
		// 原因：这里没按周期清空，因此链路丢失也一直会保存已找到的路径。
		this.netflows.clear();
		this.isisAnalysers.clear();
		this.ospfAnalysers.clear();
	}

	/**
	 * 根据上一个周期得到的需要提前计算的源——目的list映射，用新的拓扑提前计算最短路径
	 * 
	 */
	public void ospfPreCalculate() {
		resetMaterials();

		int size = this.ospfTopo.getRouterCount();// 获得全网路由器总数

		if (size == 0) {
			logger.warning("no router in topo!");
			return;
		}

		this.index = 0;// 索引从零开始记
		this.allRouterIds = this.ospfTopo.getAllRouterIds();// 得到全部路由器id列表，供n个线程互斥访问
		this.divideCount = (MainProcesser.DIVIDE_COUNT == 0) ? 3
				: MainProcesser.DIVIDE_COUNT;

		for (int i = 0; i < this.divideCount; i++) {
			OspfAnalyser ospfAnalyser = new OspfAnalyser(this, true);// 第二个参数决定是否是提前分析路径
			new Thread(ospfAnalyser).start();// 线程开始运行
		}
	}

	public void isisPreCalculate() {
		resetMaterials();

		int size = this.isisTopo.getRouterCount();// 获得全网路由器总数

		if (size == 0) {
			logger.warning("no router in topo!");
			return;
		}

		this.index = 0;// 索引从零开始记
		this.allRouterIds = this.ospfTopo.getAllRouterIds();// 得到全部路由器id列表，供n个线程互斥访问
		this.divideCount = (MainProcesser.DIVIDE_COUNT == 0) ? 3
				: MainProcesser.DIVIDE_COUNT;

		for (int i = 0; i < this.divideCount; i++) {
			IsisAnalyser isisAnalyser = new IsisAnalyser(this, true);// 第二个参数决定是否是提前分析路径
			new Thread(isisAnalyser).start();// 线程开始运行
		}
	}

	public void ospfRouteCalculate(long period) {
		int eachSize = 0;
		this.period = period;
		OspfAnalyser ospfAnalyser = null;// 临时变量
		int flowSize = this.netflows.size(); // 获得全部netflow的条目总数
		this.divideCount = (MainProcesser.DIVIDE_COUNT == 0) ? 3
				: MainProcesser.DIVIDE_COUNT;

		if (flowSize < SINGLE_COUNT) {
			ospfAnalyser = new OspfAnalyser(this, false);
			ospfAnalyser.setNetflow(this.netflows);// 设置netflow数据
			new Thread(ospfAnalyser).start();// 线程开始运行
			gatherResult(ospfAnalyser);
		} else {
			eachSize = flowSize / this.divideCount;// 将条目总数分成若干份，每份条目数

			for (int i = 0; i < this.divideCount; i++) {// 为每份netflow分别起一个RouteAnalysis线程
				ospfAnalyser = new OspfAnalyser(this, false);
				ospfAnalyser.setNetflow(this.netflows.subList(i * eachSize,
						(i + 1) * eachSize));// 设置netflow数据
				this.ospfAnalysers.add(ospfAnalyser);// 加入列表集中管理
				new Thread(ospfAnalyser).start();// 线程开始运行
			}

			for (int i = 0; i < this.divideCount; i++) {
				ospfAnalyser = this.ospfAnalysers.get(i);
				gatherResult(ospfAnalyser);
			}
		}

	}

	public void isisRouteCalculate(long pid) {
		this.period = pid;
		int eachSize = 0;
		int flowSize = this.netflows.size(); // 获得全部netflow的条目总数
		IsisAnalyser isisAnalyser = null;// isis路径分析类
		this.divideCount = (MainProcesser.DIVIDE_COUNT == 0) ? 3
				: MainProcesser.DIVIDE_COUNT;

		if (flowSize < SINGLE_COUNT) {// 如果流大小小于一定数量（待定），只分给一个analyser计算
			isisAnalyser = new IsisAnalyser(this, false);
			isisAnalyser.setNetflow(this.netflows);// 设置netflow数据
			new Thread(isisAnalyser).start();// 线程开始运行
			gatherResult(isisAnalyser);// 手机结果
		} else {
			eachSize = flowSize / this.divideCount;// 将条目总数分成若干份，每份条目数

			for (int i = 0; i < this.divideCount; i++) {// 为每份netflow分别起一个RouteAnalysis线程
				isisAnalyser = new IsisAnalyser(this, false);
				isisAnalyser.setNetflow(this.netflows.subList(i * eachSize,
						(i + 1) * eachSize));// 设置netflow数据
				this.isisAnalysers.add(isisAnalyser);// 加入列表集中管理
				new Thread(isisAnalyser).start();// 线程开始运行
			}

			for (int i = 0; i < this.divideCount; i++) {
				isisAnalyser = this.isisAnalysers.get(i);
				gatherResult(isisAnalyser);
			}
		}

	}

	public void gatherResult(IsisAnalyser isisAnalyser) {
		isisAnalyser.completedSignal();// 如果完成了
		gatherLidTraffic(isisAnalyser.getMapLidTraffic());// 与主线程中保存这一结果的映射合并，相同id的flow叠加
	}

	/**
	 * 
	 * 
	 * @param ospfAnalyser
	 */
	private void gatherResult(OspfAnalyser ospfAnalyser) {
		ospfAnalyser.completedSignal();// 如果已经分析完了
		gatherLidTraffic(ospfAnalyser.getMapLidTraffic());// 与主线程中保存这一结果的映射合并，相同id的flow叠加
	}

	/**
	 * 各个计算线程向主线程的foundPath缓存中插入数据
	 * 
	 * @param ids
	 *            源id+“_”+目的id
	 * @param path
	 *            源到目的路径
	 */
	public synchronized void insertFoundPath(String ids, Path path) {
		this.foundPath.put(ids, path);
	}

	/**
	 * 根据源id+“_”+目的id字符串找到缓存的path，如果没有返回空
	 * 
	 * @param ids
	 *            源id+“_”+目的id字符串
	 * @return 缓存的path，如果没有返回空
	 */
	public synchronized Path getPathByIds(String ids) {
		return this.foundPath.get(ids);
	}

	/**
	 * 一次向foundPath插入多于一条的记录
	 * 
	 * @param paths
	 */
	public synchronized void insertMorePath(HashMap<String, Path> paths) {
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

			if (id != 0 && toAdd != null && mapLidTlink.containsKey(id)) {
				inArr = this.mapLidTlink.get(id);

				if (inArr == null) {
					this.mapLidTlink.put(id, toAdd);
				} else {
					inArr.combineTraffic(toAdd);// 有则累加
				}
			}
		}
	}

	/**
	 * @return Returns the mapProtocalBytes.
	 */
	@SuppressWarnings("unchecked")
	public HashMap<String, Long> getMapProtocalBytes() {
		return (HashMap<String, Long>) mapProtocalBytes.clone();
	}

	private int index = 0;// 当前已经分析到的路由器id在列表中的索引

	public synchronized long getOneRouterId() {
		if (index < this.allRouterIds.size()) {
			return this.allRouterIds.get(index++);
		}
		return -1;
	}

	public void setNetflows(ArrayList<Netflow> flows) {
		this.netflows = flows;
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
	 * @return Returns the ospfTopo.
	 */
	public OspfTopo getOspfTopo() {
		return ospfTopo;
	}

	/**
	 * @return Returns the period.
	 */
	public long getPeriod() {
		return period;
	}

	/**
	 * @return Returns the isisTopo.
	 */
	public IsisTopo getIsisTopo() {
		return isisTopo;
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
}
