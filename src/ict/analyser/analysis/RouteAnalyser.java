/*
 * Filename: RouteAnalyser.java
 * Copyright: ICT (c) 2012-11-22
 * Description: 
 * Author: 25hours
 */
package ict.analyser.analysis;

import ict.analyser.flow.Flow;
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

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-11-22
 */
public class RouteAnalyser {

	private int topN = 0;

	private long period = 0;

	private int divideCount = 0;

	private int singleCount = 1000;// 流数量小于singleCount的只需要一个analyser就能执行，待定

	private OspfTopo ospfTopo = null;

	private IsisTopo isisTopo = null;

	private ArrayList<Flow> allFlows = null;// 保存当前周期分析出的全部flow路径

	private ArrayList<Flow> topNFlows = null;// top n条流路径,返回给主程序的

	private HashMap<String, Path> foundPath = null;// key是源路由器id+“_”+目的路由器id

	private ArrayList<Netflow> netflows = null;// flow接收模块分析并聚合后得到的报文对象列表

	private HashMap<Long, SpfSnapShot> mapSrcSpf = null;// 优化：保存源为根的spf计算过程的快照，之所以是快照，是因为每次spf只计算到到特定目的id就停止，将这个瞬间保存，下一次在这个瞬间开始计算

	private HashMap<Integer, TrafficLink> mapLidTlink = null;// link id ——

	private ArrayList<OspfAnalyser> ospfAnalysers = null;// 维护一个所有正在运行的分析线程的列表

	private ArrayList<IsisAnalyser> isisAnalysers = null;// 维护一个所有正在运行的分析线程的列表

	private HashMap<Long, ArrayList<Long>> mapPreCalId = null;

	public RouteAnalyser() {
		this.allFlows = new ArrayList<Flow>();
		this.topNFlows = new ArrayList<Flow>();
		this.netflows = new ArrayList<Netflow>();
		this.foundPath = new HashMap<String, Path>();
		this.ospfAnalysers = new ArrayList<OspfAnalyser>();
		this.isisAnalysers = new ArrayList<IsisAnalyser>();
		this.mapSrcSpf = new HashMap<Long, SpfSnapShot>();
		this.mapLidTlink = new HashMap<Integer, TrafficLink>();
		this.mapPreCalId = new HashMap<Long, ArrayList<Long>>();
	}

	public void resetMaterials() {
		this.foundPath.clear();// 这里去掉bug现象是：结果上报了本周起没有的链路。
								// 原因：这里没按周期清空，因此链路丢失也一直会保存已找到的路径。
		this.allFlows.clear();
		this.netflows.clear();
		this.mapSrcSpf.clear();
		this.topNFlows.clear();
		this.isisAnalysers.clear();
		this.ospfAnalysers.clear();
	}

	/**
	 * 根据上一个周期得到的需要提前计算的源——目的list映射，用新的拓扑提前计算最短路径
	 * 
	 */
	public void ospfPreCalculate() {

		resetMaterials();

		int index = 0; // 表示分割点，这里要将主中的mapprecal分割成divideCount份
		int eachSize = 0;
		int size = this.mapPreCalId.size();// 得到总entry数
		OspfAnalyser ospfAnalyser = null;// 以下为临时变量
		this.divideCount = (MainProcesser.divideCount == 0) ? 3
				: MainProcesser.divideCount;

		if (size <= this.singleCount) {
			ospfAnalyser = new OspfAnalyser(this.ospfTopo, this);// 初始化一个分析类
			ospfAnalyser.setPreCalMap(this.mapPreCalId);// 设定提前计算的map
			new Thread(ospfAnalyser).start();// 线程开始运行
		} else {
			eachSize = size / this.divideCount;// 将条目总数分成若干份，每份条目数
			Map.Entry<Long, ArrayList<Long>> entry = null;
			Iterator<Entry<Long, ArrayList<Long>>> iter = this.mapPreCalId
					.entrySet().iterator();
			HashMap<Long, ArrayList<Long>> tempPreCalMap = new HashMap<Long, ArrayList<Long>>();

			while (iter.hasNext()) {

				index++;
				entry = iter.next();

				tempPreCalMap.put(entry.getKey(), entry.getValue());// 从主中的map一条条赋值到临时map中

				if (index == eachSize) { // 赋值到一定数量了,这里有点笨，考虑优化
					ospfAnalyser = new OspfAnalyser(this.ospfTopo, this);// 初始化一个分析类
					ospfAnalyser.setPreCalMap(tempPreCalMap);// 设定提前计算的map
					new Thread(ospfAnalyser).start();// 线程开始运行
					// 重置变量
					tempPreCalMap = new HashMap<Long, ArrayList<Long>>();
					index = 0;
				}
			}
		}
	}

	public void isisPreCalculate() {

		resetMaterials();

		int index = 0; // 表示分割点，这里要将主中的mapprecal分割成divideCount份
		int eachSize = 0;
		IsisAnalyser isisAnalyser = null;// 以下为临时变量
		this.divideCount = (MainProcesser.divideCount == 0) ? 3
				: MainProcesser.divideCount;
		int size = this.mapPreCalId.size();// 得到总entry数

		if (size <= this.singleCount) {
			isisAnalyser = new IsisAnalyser(this.isisTopo, this);// 初始化一个分析类
			isisAnalyser.setPreCalMap(this.mapPreCalId);// 设定提前计算的map
			new Thread(isisAnalyser).start();// 线程开始运行
		} else {
			eachSize = size / this.divideCount;// 将条目总数分成若干份，每份条目数
			Map.Entry<Long, ArrayList<Long>> entry = null;
			Iterator<Entry<Long, ArrayList<Long>>> iter = this.mapPreCalId
					.entrySet().iterator();
			HashMap<Long, ArrayList<Long>> tempPreCalMap = new HashMap<Long, ArrayList<Long>>();

			while (iter.hasNext()) {
				index++;
				entry = iter.next();

				tempPreCalMap.put(entry.getKey(), entry.getValue());// 从主中的map一条条赋值到临时map中

				if (index == eachSize) { // 赋值到一定数量了,这里有点笨，考虑该
					isisAnalyser = new IsisAnalyser(this.isisTopo, this);// 初始化一个分析类
					isisAnalyser.setPreCalMap(tempPreCalMap);// 设定提前计算的map
					// this.isisPreAnalysers.add(isisAnalyser);// 加入列表集中管理
					new Thread(isisAnalyser).start();// 线程开始运行
					// 重置变量
					tempPreCalMap = new HashMap<Long, ArrayList<Long>>();
					index = 0;
				}
			}
		}
	}

	public void ospfRouteCalculate(long period) {

		int eachSize = 0;
		this.period = period;
		int flowSize = this.netflows.size(); // 获得全部netflow的条目总数
		OspfAnalyser ospfAnalyser = null;// 临时变量
		this.divideCount = (MainProcesser.divideCount == 0) ? 3
				: MainProcesser.divideCount;

		if (flowSize < this.singleCount) {
			ospfAnalyser = new OspfAnalyser(this.period, this.topN, this);
			ospfAnalyser.setTopo(this.ospfTopo);// 为线程设置topo数据
			ospfAnalyser.setNetflow(this.netflows);// 设置netflow数据
			new Thread(ospfAnalyser).start();// 线程开始运行
			gatherResult(ospfAnalyser);
		} else {

			eachSize = flowSize / this.divideCount;// 将条目总数分成若干份，每份条目数

			for (int i = 0; i < this.divideCount; i++) {// 为每份netflow分别起一个RouteAnalysis线程
				ospfAnalyser = new OspfAnalyser(this.period, this.topN, this);
				ospfAnalyser.setTopo(this.ospfTopo);// 为线程设置topo数据
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

		this.divideCount = (MainProcesser.divideCount == 0) ? 3
				: MainProcesser.divideCount;

		int eachSize = 0;
		this.period = pid;
		int flowSize = this.netflows.size(); // 获得全部netflow的条目总数
		IsisAnalyser isisAnalyser = null;// isis路径分析类

		if (flowSize < this.singleCount) {// 如果流大小小于一定数量（待定），只分给一个analyser计算
			isisAnalyser = new IsisAnalyser(this.period, this.topN, this);
			isisAnalyser.setTopo(this.isisTopo);// 为线程设置topo数据
			isisAnalyser.setNetflow(this.netflows);// 设置netflow数据
			new Thread(isisAnalyser).start();// 线程开始运行
			gatherResult(isisAnalyser);// 手机结果
		} else {
			eachSize = flowSize / this.divideCount;// 将条目总数分成若干份，每份条目数

			for (int i = 0; i < this.divideCount; i++) {// 为每份netflow分别起一个RouteAnalysis线程
				isisAnalyser = new IsisAnalyser(this.period, this.topN, this);
				isisAnalyser.setTopo(this.isisTopo);// 为线程设置topo数据
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
		// ArrayList<Flow> topnFlow = null;// 保存第一个周期得到的topN流的信息临时变量
		HashMap<Integer, TrafficLink> mapLidTraffic = null;
		HashMap<Long, ArrayList<Long>> preCalIds = null;// 保存需要第二个周期拓扑接收到后就直接算路径的源和目的id临时变量

		isisAnalyser.completedSignal();// 如果完成了

		mapLidTraffic = isisAnalyser.getMapLidTraffic();// 从分析线程中获得所有的link
		// id——byte映射
		preCalIds = isisAnalyser.getPreCalIdList();// 获得需要提前计算的源——目的路由器id

		// topnFlow = isisAnalyser.getTopNFlows();// 获得topN的流

		gatherLidTraffic(mapLidTraffic);// 与主线程中保存这一结果的映射合并，相同id的flow叠加

		gatherPreCalMap(preCalIds); // 与主线程中保存这一结果的映射合并

		// calTopnFlow(topnFlow);// 将TopN流与主线程总保存的topN流汇总
	}

	/**
	 * 
	 * 
	 * @param ospfAnalyser
	 */
	private void gatherResult(OspfAnalyser ospfAnalyser) {

		// ArrayList<Flow> flows = null;// 保存一个analyser得到的全部flow路径
		// ArrayList<Flow> topnFlow = null;// 保存第一个周期得到的topN流的信息临时变量
		// HashMap<Integer, Long> linkIdByte = null;// 保存link

		HashMap<Integer, TrafficLink> mapLidTraffic = null;
		HashMap<Long, ArrayList<Long>> preCalIds = null;// 保存需要第二个周期拓扑接收到后就直接算路径的源和目的id临时变量

		ospfAnalyser.completedSignal();// 如果已经分析完了

		// foundPath = analyser.getFoundPath();// 从分析线程中过得已找到的路径缓存
		mapLidTraffic = ospfAnalyser.getMapLidTraffic();// 从分析线程中获得所有的link
														// id——byte映射
		preCalIds = ospfAnalyser.getPreCalIdList();// 获得需要提前计算的源——目的路由器id

		// topnFlow = ospfAnalyser.getTopNFlows();// 获得topN的流

		// flows = ospfAnalyser.getAllFlows();// 获得全部流
		// gatherFoundPath(foundPath);

		gatherLidTraffic(mapLidTraffic);// 与主线程中保存这一结果的映射合并，相同id的flow叠加

		gatherPreCalMap(preCalIds); // 与主线程中保存这一结果的映射合并

		// gatherAllFlows(flows);// 与主分析类保存这一结果的列表合并

		// calTopnFlow(topnFlow);// 将TopN流与主线程总保存的topN流汇总

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
	 * 根据源路由器id查找缓存的spf快照
	 * 
	 * @param srcId
	 * @return spf快照
	 */
	public synchronized SpfSnapShot getSnapShort(long srcId) {
		return this.mapSrcSpf.get(srcId);
	}

	/**
	 * 插入某个源id对应的spf树
	 * 
	 * @param srcId
	 *            源id
	 * @param snapShort
	 *            spf
	 */
	public synchronized void insertSnapshort(Long srcId, SpfSnapShot snapShort) {
		this.mapSrcSpf.put(srcId, snapShort);
	}

	/**
	 * 将每一个routerAnalyser得到的下一个周期提前计算的源——目的id list与主线程保存的合并
	 * 
	 * @param preCalIds
	 */
	private void gatherPreCalMap(HashMap<Long, ArrayList<Long>> preCalIds) {
		// 一些临时变量
		int size = 0;
		Long srcId = null;
		Long dstId = null;
		ArrayList<Long> listToAdd = null;
		ArrayList<Long> listInMain = null;
		Iterator<Entry<Long, ArrayList<Long>>> iter = preCalIds.entrySet()
				.iterator();
		Map.Entry<Long, ArrayList<Long>> entry = null;

		while (iter.hasNext()) {// 遍历要加入的map
			entry = iter.next();
			srcId = entry.getKey(); // 得到源id
			listToAdd = entry.getValue();// 得到要加入的目的id list
			listInMain = this.mapPreCalId.get(srcId);// 得到主线程中保存到某个源id的列表
			if (listInMain != null) {// 如果主线程变量中包含源id
				size = listToAdd.size(); // 保存要加入列表的size
				for (int i = 0; i < size; i++) {// 遍历要加入的列表，如果已经在主线程中对应列表中，则跳过，否则加入列表中
					dstId = listToAdd.get(i);
					if (!listInMain.contains(dstId)) {
						listInMain.add(dstId);
					}
				}
			} else {// 如果主中不包含这个源——目的id列表对应映射，加入
				this.mapPreCalId.put(srcId, listToAdd);
				// System.out.println("gather precal mAP SRC:"
				// + IPTranslator.calLongToIp(srcId) + "  dst:"
				// + IPTranslator.calLongToIp(listToAdd.get(0)));
			}
		}
	}

	/**
	 * 将参数中传来的topN流汇总到主线程中保存TopN流的列表中
	 * 
	 * @param topnFlow
	 */
	public void calTopnFlow(ArrayList<Flow> flows) {

		if (flows == null) {
			return;
		}

		int sizeToAdd = flows.size();// 记录要插入的flow size
		int sizeInMain = this.topNFlows.size();// 记录主中的topN flow size
		int sizeAfterAdd = sizeInMain;// 记录插入操作后主topNList的元素总数

		Flow flowToAdd = null;
		Flow flowInMain = null;

		if (sizeInMain == 0) {
			this.topNFlows.addAll(flows);
		} else {
			int position = -1;

			for (int i = 0; i < sizeToAdd; i++) {// 这里写了个插入排序，从要加入的流的最大流开始比较
				position = -1;
				flowToAdd = flows.get(i);

				for (int j = sizeInMain - 1; j >= 0; j--) {// 从主线程保存的列表中flow最小的flow开始比较
					flowInMain = this.topNFlows.get(j);
					if (flowToAdd.compareTo(flowInMain)) {// 如果要加入的flow大于当前要比较的主线程的流
						position = j;// 记录要加入的这条flow加入的位置
					} else {
						break;// 否则跳出循环
					}
				}

				if (position == -1) {// 如果这条流没插入到主线程topN
										// 列表中，那么要加入的流后面的（flow比它小的流都不插入了）
					break;
				}

				this.topNFlows.add(position, flowToAdd);
				sizeAfterAdd++;

				if (sizeAfterAdd > this.topN) { // 如果插入后使主中的元素数多于topN个，删除最后一个
					this.topNFlows.remove(sizeAfterAdd - 1);
				}
				sizeAfterAdd--;
			}
		}
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

			if (id != 0 && toAdd != null) {
				inArr = this.mapLidTlink.get(id);

				// if (inArr == null) {//modified 20130822
				// 由于topo中的全部链路都应该出现，所以如果没出现 是异常情况
				// this.mapLidTlink.put(id, toAdd);// 如果没有这条流量的traffic信息，则添加
				// } else {
				if (inArr == null) {
					System.out.println("link id:" + id + "  not in topo");
					return;
				}

				inArr.combineTraffic(toAdd);// 有则累加
				// }
			}
		}
	}

	// /**
	// *
	// *
	// * @param flows
	// */
	// private void gatherAllFlows(ArrayList<Flow> flows) {
	// if (flows != null) {
	// this.allFlows.addAll(flows);
	// }
	// }

	public void setNetflows(ArrayList<Netflow> flows) {
		this.netflows = flows;
	}

	public void setTopo(OspfTopo topo) {
		this.ospfTopo = topo;
	}

	public void setTopo(IsisTopo topo) {
		this.isisTopo = topo;
	}

	public void setTopN(int topN) {
		this.topN = topN;
	}

	/**
	 * @return Returns the topNFlows.
	 */
	public ArrayList<Flow> getTopNFlows() {
		return topNFlows;
	}

	/**
	 * @return Returns the mapLidTlink.
	 */
	public HashMap<Integer, TrafficLink> getMapLidTlink() {
		return mapLidTlink;
	}

	/**
	 * @param mapLidTlink
	 *            The mapLidTlink to set.
	 */
	public void setMapLidTlink(HashMap<Integer, TrafficLink> mapLidTlink) {
		this.mapLidTlink = mapLidTlink;
	}

}
