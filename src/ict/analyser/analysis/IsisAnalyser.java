/*
 * Filename: IsisAnalyser.java
 * Copyright: ICT (c) 2012-11-25
 * Description: 
 * Author: 25hours
 */
package ict.analyser.analysis;

import ict.analyser.common.Constant;
import ict.analyser.common.Vertex;
import ict.analyser.database.DBOperator;
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
	private long period = 0;
	private IsisTopo topo = null;
	private Lock flowLock = null;
	private DBOperator dbWriter = null;
	private Lock completeLock = null;
	private boolean isPreCal = false;
	private boolean completed = false;
	private Condition completeCon = null;// 锁相关：设置等待唤醒，相当于wait/notify
	private List<Netflow> netflows = null;// netflow接收模块分析并聚合后得到的报文对象列表
	private RouteAnalyser processer = null;
	private ArrayList<Flow> allFlowRoute = null;// 全部flow的route
	private HashMap<Integer, TrafficLink> mapLidTlink = null;// link id ——
	private Logger logger = Logger.getLogger(IsisAnalyser.class.getName());// 注册一个logger

	/**
	 * 重载构造函数
	 * 
	 * @param mainProcesser
	 */
	public IsisAnalyser(RouteAnalyser processer, boolean isPrecal) {
		this.isPreCal = isPrecal;
		this.processer = processer;
		this.period = processer.getPeriod();
		this.topo = processer.getIsisTopo();

		if (!isPrecal) { // 如果是计算流量路径需要额外初始化的变量
			this.dbWriter = new DBOperator();
			this.flowLock = new ReentrantLock();
			this.completeLock = new ReentrantLock();
			this.allFlowRoute = new ArrayList<Flow>();
			this.completeCon = completeLock.newCondition();
			this.mapLidTlink = new HashMap<Integer, TrafficLink>();
		}
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
			logger.info("prefre calculating done!");
		} else { // 否则是计算flow路径
			logger.info("flow route calculating");
			calFlowRoute();
		}

	}

	public void calTopoRoute() {
		long srcId = 0;

		while (true) {
			srcId = this.processer.getOneRouterId();

			if (srcId == -1) {
				break;
			}

			SPFCompute(srcId);
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
				netflow.printDetail();
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
				netflow.printDetail();
				logger.info("interid == 0 or srcInterface == 0");
				System.out
						.println("***************************************************\n");
				continue;
			}

			ridInter = this.topo.getRidByPrefix(netflow.getDstAddr(),
					netflow.getDstMask());

			if (ridInter == null) {
				netflow.printDetail();
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
				netflow.printDetail();
				logger.info("interid == 0 or dstInterface == 0");
				System.out
						.println("***************************************************\n");
				continue;
			}

			netflow.printDetail();

			if (srcRouterId == dstRouterId) {
				logger.info("srcRid  ==  dstRid,create a new path with cost 0");
				path = new Path();
				path.setTotalCost(0);
				// path.setSrcInterface(srcInterface);
				// path.setDstInterface(dstInterface);
				path.setSrcRouter(srcRouterId);
				// continue;
			} else {

				direction = Constant.INTERNAL_FLOW;

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

			// 将源和目的路由器存入列表，下一个周期提前计算最短路径的源和目的对列表
			if (srcRouterId != dstRouterId) {
				// path.setSrcInterface(srcInterface);// 设置源和目的路由器接口prefix
				// path.setDstInterface(dstInterface);
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
		Path path = this.processer.getPathByIds(srcId + "_" + dstId);// 在成功路径缓存中查找源和目的id对

		if (path == null) {// 如果源和目的在成功路径缓存中，遍历链路，添加flow
			logger.warning("path for src id:" + IPTranslator.calLongToIp(srcId)
					+ "  dst id:" + IPTranslator.calLongToIp(dstId)
					+ "  not found!");
			return null;
		}

		return path;
	}

	// 这里有个优化，将每个源的每次spf算法结束后的最优结构和candidate保存起来，这样下一次计算时，如果源曾经计算过，
	// 但是之前计算过程中没计算到将本次的目的id加入到spf中（如果加过了，上面foundpath已经缓存直接能找到，无需再spf了）则得到本地保存上一次计算快照（spfmap
	// 和candidatemap）在此基础上继续计算

	public void SPFCompute(long srcId) {// 已改
		if (srcId == -1) {
			logger.warning("src router id is invalid!");
			return;
		}

		IsisRouter srcRouter = this.topo.getRouterById(srcId);

		if (srcRouter == null) {
			logger.warning("cannot find router for id:"
					+ IPTranslator.calLongToIp(srcId));
			return;
		}

		// 临时变量
		long neighborId = 0;// 邻居设备id
		Vertex candidate = null;// 一次循环中从candidate集合中选中的
		Link neighborLink = null;// 链路对象
		IsisRouter router = null;// 路由器对象
		ArrayList<Link> neighbors = null;// 保存邻居链路
		ArrayList<Link> linksOnPath = null;
		// 分析过程中使用的变量
		HashMap<Long, Vertex> spfTree = new HashMap<Long, Vertex>();// 最优路径上的路由器id——路由器对象
		HashMap<Long, Vertex> candidatesMap = new HashMap<Long, Vertex>();// candidate集合中路由器id——路由器对象
		Vertex vertex = new Vertex(0);// 初始化一个vertex对象
		vertex.setNeighbor(srcRouter.getLinks());// 根据router对象中的链路初始化vertex对象中的neighbor信息
		vertex.setRouterId(srcId);// 设置路由器id

		candidatesMap.put(srcId, vertex);// 放到候选对象映射中

		while (!candidatesMap.isEmpty()) {// 如果candidate列表不为空
			candidate = getMinMetricId(candidatesMap);// 从candidate中得到到root距离最小的设备的id

			linksOnPath = candidate.getPath().getLinks();// 得到路径上的链路
			candidatesMap.remove(candidate.getRouterId());// 从候选数组中删除这个candidate
			spfTree.put(candidate.getRouterId(), candidate);// 添加到最优路径路由器id列表中
			this.processer.insertFoundPath(
					srcId + "_" + candidate.getRouterId(), candidate.getPath());// 添加到RouteAnalyser中保存全部的路径中

			neighbors = candidate.getNeighbor();// 得到candidate的全部neighbor
			int size = neighbors.size();// 记录neighbor的个数

			for (int i = 0; i < size; i++) {// 遍历neighbor
				neighborLink = neighbors.get(i);// 得到一个neighbor
				neighborId = neighborLink.getNeighborId();// 得到neighbor id

				if (spfTree.containsKey(neighborId)) {// 如果邻居已经在spf树中，跳过
					continue;
				}

				router = this.topo.getRouterById(neighborId);

				if (router == null) {// 如果为空，报错，分析下一个邻居
					logger.warning(IPTranslator.calLongToIp(candidate
							.getRouterId())
							+ " neighbor router is not found!"
							+ IPTranslator.calLongToIp(neighborId));
					continue;
				}

				int cost1 = candidate.getTotalcost()
						+ +neighborLink.getMetric();// 如果经过刚加入spf中的节点，总cost值

				vertex = candidatesMap.get(neighborId);// 在candidate中查找这个邻居

				if (vertex != null) {// 如果邻居已经在candidate中
					int cost2 = vertex.getTotalcost();// 不经所上一个加入到spf中的节点到远点的路径

					if (cost1 < cost2) {// 如果经过刚加入spf节点路径更短，做相应更新
						vertex.setPath(linksOnPath);
						vertex.addLink(neighborLink);
						vertex.setTotalcost(cost1);
					}
				} else {// 如果不在candidate中
					vertex = new Vertex();// new 一个vertex对象
					vertex.setRouterId(neighborId);// 设置vertex的设备id
					vertex.setPath(linksOnPath);
					vertex.addLink(neighborLink);
					vertex.setNeighbor(router.getLinks());// 设置该vertex的邻居
					vertex.setTotalcost(candidate.getTotalcost()
							+ neighborLink.getMetric());

					candidatesMap.put(neighborId, vertex);// 将这个邻居加入到candidate中
				}
			}
		}
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
	 * @param mapLinkIdBytes
	 *            The mapLinkIdBytes to set. 如果端口号为0，则算other类流量
	 */
	public void setMapLidTraffic(int linkId, long bytes, int port) {
		if (linkId == 0 || bytes == 0) {
			return;
		}

		TrafficLink link = this.mapLidTlink.get(linkId);

		if (link != null) {
			// link.addTraffic(bytes, port);
		} else {
			link = new TrafficLink(linkId);
			// link.addTraffic(bytes, port);
			this.mapLidTlink.put(linkId, link);
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
		this.dbWriter.writeFlowToDB(this.allFlowRoute);
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
	 * @return Returns the mapLinkIdBytes.
	 */
	public HashMap<Integer, TrafficLink> getMapLidTraffic() {
		return this.mapLidTlink;
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
