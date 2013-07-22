/*
 * Filename: IsisAnalyser.java
 * Copyright: ICT (c) 2012-11-25
 * Description: 
 * Author: 25hours
 */
package ict.analyser.analysis;

import ict.analyser.database.DBWriter;
import ict.analyser.flow.Flow;
import ict.analyser.flow.Path;
import ict.analyser.flow.TrafficLink;
import ict.analyser.isistopo.IsisRouter;
import ict.analyser.isistopo.IsisTopo;
import ict.analyser.netflow.Netflow;
import ict.analyser.ospftopo.Link;
import ict.analyser.tools.IPTranslator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-11-25
 */
public class IsisAnalyser implements Runnable {

	private Logger logger = Logger.getLogger(IsisAnalyser.class.getName());// 注册一个logger

	private int topN = 0;

	private long period = 0;

	private IsisTopo topo = null;

	private boolean isPreCal = false;

	private boolean completed = false;

	private RouteAnalyser processer = null;

	private Lock completeLock = null;

	private Lock flowLock = null;

	private DBWriter dbWriter = null;

	private Condition completeCon = null;// 锁相关：设置等待唤醒，相当于wait/notify

	private List<Netflow> netflows = null;// netflow接收模块分析并聚合后得到的报文对象列表

	private ArrayList<Flow> topNFlows = null;// top n条flow route

	private ArrayList<Long> topNBytes = null;// topN flow的bytes

	private ArrayList<Flow> allFlowRoute = null;// 全部flow的route

	private ArrayList<String> unfoundPath = null;// key是源路由器id+“_”+目的路由器id

	// private HashMap<String, Path> foundPath = null;// key是源路由器id+“_”+目的路由器id

	private HashMap<Long, SpfSnapShot> mapSrcSpf = null;
	// 优化：保存源为根的spf计算过程的快照，之所以是快照，是因为每次spf只计算到到特定目的id就停止，将这个瞬间保存，下一次在这个瞬间开始计算
	private HashMap<Integer, TrafficLink> mapLidTlink = null;// link id ——

	private HashMap<Long, ArrayList<Long>> mapPreCalId = null;// 下一个周期提前计算最短路径的源和目的对列表,这里设计成hash，源id——目的idlist映射，这样在下一次计算的时候可以在一个spf之内找到多个目的

	/**
	 * 重载构造函数
	 * 
	 * @param mainProcesser
	 */
	public IsisAnalyser(long pid, int topN, RouteAnalyser processer) {
		// 初始化
		this.period = pid;
		this.topN = topN;
		this.isPreCal = false;
		this.processer = processer;
		this.dbWriter = new DBWriter();
		this.topNFlows = new ArrayList<Flow>();
		this.topNBytes = new ArrayList<Long>();
		this.flowLock = new ReentrantLock();
		this.completeLock = new ReentrantLock();
		this.completeCon = completeLock.newCondition();
		this.allFlowRoute = new ArrayList<Flow>();
		this.unfoundPath = new ArrayList<String>();
		// this.foundPath = new HashMap<String, Path>();
		this.mapLidTlink = new HashMap<Integer, TrafficLink>();
		this.mapPreCalId = new HashMap<Long, ArrayList<Long>>();
	}

	/**
	 * 重载构造函数
	 * 
	 * @param mainProcesser
	 */
	public IsisAnalyser(IsisTopo topo, RouteAnalyser processer) {
		this.isPreCal = true;
		this.topo = topo;
		this.processer = processer;
		this.unfoundPath = new ArrayList<String>();
		// this.foundPath = new HashMap<String, Path>();
		this.mapSrcSpf = new HashMap<Long, SpfSnapShot>();
	}

	/**
	 * 主分析函数
	 * 
	 */
	@Override
	public void run() {

		if (isPreCal) {// 如果是topo提前计算
			logger.info("prefre calculating");
			calTopoRoute();
		} else { // 否则是计算flow路径
			logger.info("flow route calculating");
			calFlowRoute();
		}

	}

	public void calTopoRoute() {

		if (this.mapPreCalId == null || this.mapPreCalId.size() == 0) {
			// logger.info("mapPreCalId is null!");
			return;
		}

		long srcId = 0;
		ArrayList<Long> dstIds = null;
		Map.Entry<Long, ArrayList<Long>> entry = null;
		Iterator<Entry<Long, ArrayList<Long>>> iter = this.mapPreCalId
				.entrySet().iterator();

		while (iter.hasNext()) {// 遍历要加入的map
			entry = iter.next();
			srcId = entry.getKey(); // 得到源id
			dstIds = entry.getValue();
			// System.out.println("precal   src:"
			// + IPTranslator.calLongToIp(srcId) + "  dst:"
			// + IPTranslator.calLongToIp(dstIds.get(0)));
			preCalShortest(srcId, dstIds);
		}
		System.out.println("precal done!!!!!!!!!!");
	}

	public void preCalShortest(long srcId, ArrayList<Long> dstIds) {

		if (srcId == 0 || dstIds == null || dstIds.size() == 0) {
			return;
		}

		long dstId = 0;
		Path path = null;
		int size = dstIds.size();

		for (int i = 0; i < size; i++) {

			dstId = dstIds.get(i);

			if (dstId != 0) {
				path = SPFCompute(srcId, dstId);
			}

			if (path != null && path.getLinks().size() != 0) {
				processer.insertFoundPath(srcId + "_" + dstId, path);// 如果找到路径，加入成功路径缓存
			}
		}
	}

	public void calFlowRoute() {

		// if (this.topo.getNetworkType() == 1) {
		// calL1Flow();
		// } else {
		// calL2Flow();
		// }

		if (this.topo.getNetworkType() == 1) {
			calL1Flow();
		}

	}

	public void calL1Flow() {

		int direction = 0;// 记录flow种类，internal:1,inbound:2,outbound:3,transit:4
		long srcRouterId = 0;
		long dstRouterId = 0;
		long srcInterface = 0;// 源路由器接口前缀
		long dstInterface = 0;// 目的路由器接口前缀
		long[] ridInter = null;
		int flowCount = this.netflows.size();// 得到聚合后的netflow列表的条目总数
		Path path = null;
		Netflow netflow = null;// 临时变量

		for (int i = 0; i < flowCount; i++) { // 开始遍历，逐条分析路径
			// 重置临时变量
			direction = 0;// 记录flow种类，internal:1,inbound:2,outbound:3,transit:4
			srcRouterId = 0;
			dstRouterId = 0;
			srcInterface = 0;
			dstInterface = 0;
			// 开始分析
			netflow = this.netflows.get(i);// 取得一条流

			ridInter = this.topo.getRidByPrefix(netflow.getSrcAddr(),
					netflow.getSrcMask());
			// 注：chuyang中全网都是l2网络，因此只有域内流量，如果根据prefix找不到路由器则跳过
			if (ridInter == null) {
				netflow.getDetail();
				logger.info("cannot find prefix for src :"
						+ netflow.getSrcAddr() + "  "
						+ IPTranslator.calLongToIp((long) netflow.getSrcAddr()));
				System.out
						.println("***************************************************\n");

				continue;
			}
			srcRouterId = ridInter[0];
			srcInterface = ridInter[1];

			if (srcRouterId == 0 || srcInterface == 0) {
				netflow.getDetail();
				logger.info("interid == 0 or srcInterface == 0");
				System.out
						.println("***************************************************\n");
				continue;
			}

			ridInter = this.topo.getRidByPrefix(netflow.getDstAddr(),
					netflow.getDstMask());

			if (ridInter == null) {
				netflow.getDetail();
				logger.info("cannot find prefix for dst:"
						+ netflow.getDstAddr() + "   "
						+ IPTranslator.calLongToIp((long) netflow.getDstAddr()));
				System.out
						.println("***************************************************\n");
				continue;
			}

			dstRouterId = ridInter[0];
			dstInterface = ridInter[1];

			if (dstRouterId == 0 || dstInterface == 0) {
				netflow.getDetail();
				logger.info("interid == 0 or dstInterface == 0");
				System.out
						.println("***************************************************\n");
				continue;
			}

			netflow.getDetail();

			if (srcRouterId == dstRouterId) {
				logger.info("srcRid  ==  dstRid,create a new path with cost 0");
				path = new Path();
				path.setTotalCost(0);
				path.setSrcInterface(srcInterface);
				path.setDstInterface(dstInterface);
				path.setSrcRouter(srcRouterId);
				// continue;
			} else {

				direction = Flow.internal;

				System.out.println("src id:"
						+ this.topo.getMapLongStrId().get(srcRouterId)
						+ "  dsr id:"
						+ this.topo.getMapLongStrId().get(dstRouterId));

				path = computeInternalPath(srcRouterId, dstRouterId);

			}

			if (path == null) {
				logger.warning("cannot find path for src id: "
						+ IPTranslator.calLongToIp(srcRouterId) + "   dst id:"
						+ IPTranslator.calLongToIp(dstRouterId));
				System.out
						.println("*********************************************\n");
				continue;
			}

			if (path.getTotalCost() == Integer.MAX_VALUE) {// 没找到路径，继续分析下一个netflow
				this.unfoundPath.add(srcRouterId + "_" + dstRouterId);// 加入到失败路径缓存中
				continue;
			}

			this.processer.insertFoundPath(srcRouterId + "_" + dstRouterId,
					path);// 将路径加入成功路径缓存中
			// 将源和目的路由器存入列表，下一个周期提前计算最短路径的源和目的对列表
			if (srcRouterId != dstRouterId) {
				path.setSrcInterface(srcInterface);// 设置源和目的路由器接口prefix
				path.setDstInterface(dstInterface);

				addPreCal(srcRouterId, dstRouterId);
			}

			// 以下为调试输出

			ArrayList<Long> idsOnPath = path.getPathInIsisIpFormat();
			int size = idsOnPath.size();
			String temp = "result path:";

			for (int x = 0; x < size; x++) {
				temp += " | "
						+ this.topo.getMapLongStrId().get(idsOnPath.get(x));
			}

			System.out.println(temp);
			System.out
					.println("***************************************************\n");
			// 调试输出结束
			insertFlow(netflow, path, direction);
		}// end of for
			// 所有流量都分析完了
		sendCompleteSignal();// 通知主线程已经分析完了

		if (this.allFlowRoute.size() > 0) {
			writeToDB();// 存入数据库
		}
	}

	/**
	 * 
	 * 
	 * @param srcRouter
	 * @param brIdList
	 * @param netflow
	 * @return
	 */
	// private Path computeL1MultiDstPath(long srcId, ArrayList<Long> brIdList,
	// Netflow netflow) {
	// if (brIdList == null) {
	// return null;
	// }
	// Path path = null;
	// int size = brIdList.size();
	// long dstId = 0;// 记录目的路由器id的临时变量
	// Path bestPath = new Path();
	//
	// for (int i = 0; i < size; i++) { // 遍历所有目的路由器
	//
	// dstId = brIdList.get(i);// 得到目的地址
	// path = computeInternalPath(srcId, dstId);
	//
	// if (path == null) {
	// continue;
	// }
	//
	// if (path.getTotalCost() < bestPath.getTotalCost()) {//
	// 如果这个目的路由器得到的path的总cost小于当前最小的，则更新最优路径
	// bestPath = path;// 将当前路径赋值为最短路径
	// }
	// }
	// return bestPath;
	// }

	public Path computeL2MultiDstPath(long srcId, ArrayList<Object[]> dstMap,
			Netflow netflow) {

		Path path = null;
		int sum = 0;
		int size = dstMap.size();
		int asbrToDst = 0;
		int bestCost = Integer.MAX_VALUE;
		long dstId = 0;// 记录目的路由器id的临时变量
		Path bestPath = null;
		Object[] tempObj = new Object[2];
		// System.out.println("size:1111  " + size);
		for (int i = 0; i < size; i++) { // 遍历所有目的路由器

			tempObj = dstMap.get(i);
			dstId = (Long) tempObj[0];// 得到目的地址
			// System.out.println(" outbound!!! dst:"
			// + IPTranslator.calLongToIp(dstId));
			asbrToDst = (Integer) tempObj[1];// 得到asbr到目的路由器的metric

			path = computeInternalPath(srcId, dstId);

			if (path == null) {
				continue;
			}

			// System.out.println(" transit!!! path:" + path.getPath()
			// + "  metric:" + path.getTotalCost());
			sum = path.getTotalCost() + asbrToDst;
			// System.out.println("sum path id:"
			// + IPTranslator.calLongToSysId(path.getSourceId()) + " sum:"
			// + sum);
			if (sum < bestCost) {// 如果这个目的路由器得到的path的总cost小于当前最小的，则更新最优路径
				bestPath = path;// 将当前路径赋值为最短路径
				bestCost = sum;
			}
		}
		// System.out.println("best path:" + bestPath.getPath() + " metric:"
		// + path.getTotalCost());
		return bestPath;
	}

	public Path computeInternalPath(long srcId, long dstId) {

		Path path = null;

		if (this.unfoundPath.contains(srcId + "_" + dstId)) {// 如果源和目的对在失败路径缓存中
			logger.info(IPTranslator.calLongToIp(srcId) + " to "
					+ IPTranslator.calLongToIp(dstId)
					+ " path cannto be found!");
			return null;
		}

		path = this.processer.getPathByIds(srcId + "_" + dstId);// 在成功路径缓存中查找源和目的id对

		if (path != null) {// 如果源和目的在成功路径缓存中，遍历链路，添加flow
			// System.out.println("path found! " + path.getPath());
			return path;
		}

		path = SPFCompute(srcId, dstId);// 计算最短路径
		return path;
	}

	// 这里有个优化，将每个源的每次spf算法结束后的最优结构和candidate保存起来，这样下一次计算时，如果源曾经计算过，
	// 但是之前计算过程中没计算到将本次的目的id加入到spf中（如果加过了，上面foundpath已经缓存直接能找到，无需再spf了）则得到本地保存上一次计算快照（spfmap
	// 和candidatemap）在此基础上继续计算

	public Path SPFCompute(long srcId, long dstId) {// 已改

		IsisRouter srcRouter = this.topo.getRouterById(srcId);

		if (srcRouter == null) {
			//logger.info("src router is null!");
			return null;
		}

		// 临时变量
		int size = 0;
		int cost1 = 0;// 经过candidate节点的cost
		int cost2 = 0;// 不经过candidate的cost
		Link neighborLink = null;// 链路对象
		IsisRouter router = null;// 路由器对象
		long neighborId = 0;// 邻居设备id
		Vertex candidate = null;// 一次循环中从candidate集合中选中的
		Vertex tempVertex = null;// 新建一个srcId对应的vertex对象
		ArrayList<Link> neighbors = null;// 保存邻居链路
		ArrayList<Link> linksOnPath = null;
		HashMap<Long, Vertex> spfTree = null;// 最优路径上的路由器id——路由器对象
		HashMap<Long, Vertex> candidatesMap = null;// candidate集合中路由器id——路由器对象

		// 根据缓存的快照映射找这个源对应的spf快照
		SpfSnapShot snapShort = null;

		if (this.mapSrcSpf != null) {// 如果是precal，则从本地缓存映射中查找,
			snapShort = this.mapSrcSpf.get(srcId);
		} else {// 否则从全局缓存映射中查找
			snapShort = this.processer.getSnapShort(srcId);
		}

		if (snapShort != null) {// 如果找到了这个源对应的spf快照
			spfTree = snapShort.getSpfTree();// 用快照对象中保存的spf赋值
			candidatesMap = snapShort.getCandidatesMap();// 用快照中保存的candidate赋值
		} else {// 没找到，重新初始化
			spfTree = new HashMap<Long, Vertex>();// 最优路径上的路由器id——路由器对象
			candidatesMap = new HashMap<Long, Vertex>();// candidate集合中路由器id——路由器对象
			tempVertex = new Vertex(0);// 初始化一个vertex对象
			tempVertex.setRouterId(srcId);// 设置路由器id
			tempVertex.setNeighbor(srcRouter.getLinks());// 根据router对象中的链路初始化vertex对象中的neighbor信息
			candidatesMap.put(srcId, tempVertex);// 放到候选对象映射中
		}

		int count = candidatesMap.size();// 得到所有candidate数目，用于循环跳出条件，这样不用每次while判断循环条件时都要计算一次candidateMap的size了

		while (count != 0) {// 如果candidate列表不为空

			candidate = getMinMetricId(candidatesMap);// 从candidate中得到到root距离最小的设备的id

			// System.out.println("candidate id:"
			// + IPTranslator.calLongToIp(candidate.getRouterId()));

			if (dstId == candidate.getRouterId()) {
				// 将spftree中的节点都缓存起来,缓存的是同一个area内部的最短路径
				Map.Entry<Long, Vertex> entry = null;
				Iterator<Entry<Long, Vertex>> iter = spfTree.entrySet()
						.iterator();
				HashMap<String, Path> paths = new HashMap<String, Path>();

				while (iter.hasNext()) {
					entry = iter.next();

					if (srcId != entry.getKey()) {
						paths.put(srcId + "_" + entry.getKey(), entry
								.getValue().getPath());// 将spf中的每一个节点到源的路径都缓存下来
					}

					// this.foundPath.put(srcId + "_" + entry.getKey(), entry
					// .getValue().getPath());

					// System.out.println("put :"
					// + IPTranslator.calLongToIp(srcId) + "_"
					// + IPTranslator.calLongToIp(entry.getKey())
					// + "  path:" + entry.getValue().getPath().getPath());
				}
				if (paths.size() != 0) {
					this.processer.insertMorePath(paths);// 一次向foundPath插入多于一条的记录
				}
				// 缓存结束
				// 将当前分析“快照”记录
				snapShort = new SpfSnapShot();
				snapShort.setSpfTree(spfTree);
				snapShort.setCandidatesMap(candidatesMap);

				if (this.isPreCal) {// 如果是precal，则在本地也缓存一份
					this.mapSrcSpf.put(srcId, snapShort);
				}

				this.processer.insertSnapshort(srcId, snapShort);
				// 记录完毕
				return candidate.getPath();// 返回路径
			}

			linksOnPath = candidate.getPath().getLinks();
			candidatesMap.remove(candidate.getRouterId());// 从candidate中删除
			count--;

			spfTree.put(candidate.getRouterId(), candidate);// 添加到最优路径路由器id列表中

			neighbors = candidate.getNeighbor();// 得到candidate的全部neighbor

			size = neighbors.size();// 记录neighbor的个数

			for (int i = 0; i < size; i++) {// 遍历neighbor
				neighborLink = neighbors.get(i);// 得到一个neighbor
				neighborId = neighborLink.getNeighborId();// 得到neighbor id

				if (spfTree.containsKey(neighborId)) {// 如果邻居已经在spf树中，跳过
					continue;
				}

				// router = allRouters.get(neighborId);// 得到邻居的路由器对象
				router = this.topo.getRouterById(neighborId);
				if (router == null) {// 如果为空，报错，分析下一个邻居
					logger.info(IPTranslator.calLongToIp(candidate
							.getRouterId())
							+ " neighbor router is not found!"
							+ IPTranslator.calLongToIp(neighborId));
					continue;
				}
				// System.out.println("neighbor id:"
				// + IPTranslator.calLongToIp(router.getRouterId()));
				// if
				// (!router.getNeighborIds().contains(candidate.getRouterId()))
				// {// 如果邻居的邻居中没有candidate，不是双向的
				// continue;
				// }

				cost1 = candidate.getTotalcost() + +neighborLink.getMetric();// 如果经过刚加入spf中的节点，总cost值

				tempVertex = candidatesMap.get(neighborId);// 在candidate中查找这个邻居

				if (tempVertex != null) {// 如果邻居已经在candidate中

					cost2 = tempVertex.getTotalcost();// 不经所上一个加入到spf中的节点到远点的路径

					if (cost1 < cost2) {// 如果经过刚加入spf节点路径更短，做相应更新
						tempVertex.setPath(linksOnPath);
						tempVertex.addLink(neighborLink);
						tempVertex.setTotalcost(cost1);

						// System.out.println("vertex updated:"
						// + IPTranslator.calLongToIp(neighborId)
						// + " vertex cost:" + cost1 + "  path:"
						// + tempVertex.getPath().getPath());
					}
				} else {// 如果不在candidate中

					tempVertex = new Vertex();// new 一个vertex对象
					tempVertex.setRouterId(neighborId);// 设置vertex的设备id
					tempVertex.setPath(linksOnPath);
					tempVertex.addLink(neighborLink);//
					tempVertex.setNeighbor(router.getLinks());// 设置该vertex的邻居
					tempVertex.setTotalcost(candidate.getTotalcost()
							+ neighborLink.getMetric());

					candidatesMap.put(neighborId, tempVertex);// 将这个邻居加入到candidate中
					// System.out.println("vertex created:"
					// + IPTranslator.calLongToIp(neighborId)
					// + " vertex cost:" + tempVertex.getTotalcost()
					// + "  path:" + tempVertex.getPath().getPath());
					count++;
				}
			}
			candidate = null;
		}
		return null;
	}

	/**
	 * 从routerid——到router的距离的映射中找到到路由器最近的节点
	 * 
	 * @param candidates
	 */
	private Vertex getMinMetricId(HashMap<Long, Vertex> candidates) {

		Vertex candidate = null;
		Vertex bestCandidate = new Vertex();
		Map.Entry<Long, Vertex> entry = null;
		Iterator<Entry<Long, Vertex>> iter = candidates.entrySet().iterator();

		while (iter.hasNext()) {
			entry = iter.next();
			candidate = entry.getValue();
			if (candidate.getPath().getTotalCost() <= bestCandidate.getPath()
					.getTotalCost()) {
				bestCandidate = candidate;
			}
		}

		return bestCandidate;
	}

	public void insertFlow(Netflow netflow, Path path, int direction) {

		ArrayList<Link> links = path.getLinks();
		Link link = null;
		int size = links.size();
		int linkId = 0;

		for (int i = 0; i < size; i++) {
			link = links.get(i);
			// link.setTotalBytes(bytes);
			linkId = link.getLinkId();
			setMapLidTraffic(linkId, netflow.getdOctets(), netflow.getDstPort());
		}
		Flow flow = new Flow(this.period, netflow, path, direction);
		this.allFlowRoute.add(flow);
		// if (isInTopN(netflow.getdOctets())) {// 如果这条流的flow总大小在topn之中
		// this.topNFlows.add(flow);// 加入到topN FLOW列表中
		// }
	}

	/**
	 * 判断flow大小是不是前topN的，如果是 ，加入topNflow列表中,这里可以考虑用最小堆做
	 * 
	 * @param bytes
	 *            一条流的大小
	 * @return 返回是否加入topN条流里面
	 */
	public boolean isInTopN(long bytes) {
		int size = this.topNBytes.size();// 得到保存前topN条flow最大的flow列表
		int position = (size == 0) ? size : (size - 1);// 位置指针，先置为列表最末尾

		for (int i = size - 1; i >= 0; i--) {// 从后向前遍历列表
			if (bytes >= this.topNBytes.get(i)) {// 如果当前flow大小大于列表中这个位置的flow
				position = i;// 指针标记位置
			} else {
				break;// 否则退出
			}
		}

		this.topNBytes.add(position, bytes);// 加入列表相应位置中

		if (position <= (size - 1)) {// 如果插入了，而且链表长度已经等于topN了
			if (size == this.topN) {// 如果列表长度已经是topN了
				this.topNBytes.remove(size);// 将第topn+1个删除
			}
			return true;
		}
		return false;
	}

	/**
	 * @param mapLinkIdBytes
	 *            The mapLinkIdBytes to set.
	 *  如果端口号为0，则算other类流量
	 */
	public void setMapLidTraffic(int linkId, long bytes, int port) {
		if (linkId == 0 || bytes == 0) {
			return;
		}

		TrafficLink link = this.mapLidTlink.get(linkId);

		if (link != null) {
			link.addTraffic(bytes, port);
		} else {
			link = new TrafficLink();
			link.addTraffic(bytes, port);
			this.mapLidTlink.put(linkId, link);
		}
	}

	public void setPreCalMap(HashMap<Long, ArrayList<Long>> preCals) {
		if (preCals != null) {
			this.mapPreCalId = preCals;
		}
	}

	public void addPreCal(long srcId, long dstId) {

		// System.out.println("add to precal!!!!"
		// + IPTranslator.calLongToIp(dstId));
		ArrayList<Long> dstIds = this.mapPreCalId.get(srcId);// 根据源id 找目的列表

		if (dstIds == null) {// 如果map中不存在，初始化并加入map
			dstIds = new ArrayList<Long>();
			dstIds.add(dstId);
			this.mapPreCalId.put(srcId, dstIds);
		} else {// 存在则直接加入目的
			dstIds.add(dstId);
		}

	}

	public void sendCompleteSignal() {
		this.completeLock.lock();
		try {
			this.completed = true;
			this.completeCon.signal();
		} finally {
			this.completeLock.unlock();
		}
	}

	public void completedSignal() {
		completeLock.lock();
		try {
			while (!this.completed) {
				this.completeCon.await();
			}
			this.completed = false;
		} catch (InterruptedException e) {
			e.printStackTrace();
		} finally {
			this.completeLock.unlock();
		}
	}

	private void writeToDB() {
		this.flowLock.lock();
		this.dbWriter.writeToDB(this.allFlowRoute);
		this.flowLock.unlock();
		System.out.println("wrote to db done!!");
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public ArrayList<Flow> getAllFlows() {
		this.flowLock.lock();
		try {
			return this.allFlowRoute;
		} finally {
			this.flowLock.unlock();
		}
	}

	/**
	 * @return Returns the topNFlows.
	 */
	public ArrayList<Flow> getTopNFlows() {
		return topNFlows;
	}

	/**
	 * @return Returns the preCalIdList.
	 */
	public HashMap<Long, ArrayList<Long>> getPreCalIdList() {
		return mapPreCalId;
	}

	/**
	 * @return Returns the mapLinkIdBytes.
	 */
	public HashMap<Integer, TrafficLink> getMapLidTraffic() {
		return this.mapLidTlink;
	}

	/**
	 * @return Returns the unfoundPath.
	 */
	public ArrayList<String> getUnfoundPath() {
		return unfoundPath;
	}

	public void setTopo(IsisTopo topo) {
		this.topo = topo;
	}

	public void setNetflow(List<Netflow> netflows) {
		this.netflows = netflows;
	}

	// public void calL2Flow() {
	// int direction = 0;// 记录flow种类，internal:1,inbound:2,outbound:3,transit:4
	// long srcRouter = 0;
	// long dstRouter = 0;
	// long sendDeviceIp = 0; // 记录发送这个netflow报文的接口ip
	// int flowCount = this.netflows.size();// 得到聚合后的netflow列表的条目总数
	// Path path = null;
	// Netflow netflow = null;// 临时变量
	// ArrayList<Object[]> dstIdMetric = null;
	//
	// for (int i = 0; i < flowCount; i++) { // 开始遍历，逐条分析路径
	// // 重置临时变量
	// srcRouter = 0;
	// dstRouter = 0;
	// dstIdMetric = null;// 清空map
	// // 开始分析
	// netflow = this.netflows.get(i);// 取得一条流
	//
	// direction = Flow.transit;
	//
	// sendDeviceIp = netflow.getRouterIP();// 得到发送这个netflow报文的接口ip
	// // srcRouter = this.topo.getBrIdByIp(sendDeviceIp);// 在映射中查找对应设备id
	// srcRouter = this.topo.getRidByPrefix(sendDeviceIp, (byte) 255);
	//
	// if (srcRouter == 0) {
	// continue;
	// }
	//
	// dstIdMetric = topo.getBrByPrefix(netflow.getDstAddr(),
	// netflow.getDstMask());
	//
	// if (dstIdMetric == null || dstIdMetric.size() == 0) {
	// System.out.println("dst router is zero");
	// continue;
	// }
	// // System.out.println("transit!!! src router id:"
	// // + IPTranslator.calLongToSysId(srcRouter)
	// // + "   dst router id:" + dstIdMetric.size());
	// path = computeL2MultiDstPath(srcRouter, dstIdMetric, netflow);
	//
	// if (path == null || path.getLinks().size() == 0) {// 没找到路径，继续分析下一个netflow
	// this.unfoundPath.add(srcRouter + "_" + dstRouter);// 加入到失败路径缓存中
	// continue;
	// }
	//
	// this.processer.insertFoundPath(srcRouter + "_" + dstRouter, path);//
	// 将路径加入成功路径缓存中
	// // 将源和目的路由器存入列表，下一个周期提前计算最短路径的源和目的对列表
	// addPreCal(srcRouter, dstRouter);
	//
	// System.out.println("result path:" + path.getPathInIpFormat());
	//
	// insertFlow(netflow, path, direction);
	// }// end of for
	// // 所有流量都分析完了
	// sendCompleteSignal();// 通知主线程已经分析完了
	//
	// if (this.allFlowRoute.size() > 0) {
	// writeToDB();// 存入数据库
	// }
	// // writeToDB();// 存入数据库
	// }
}
