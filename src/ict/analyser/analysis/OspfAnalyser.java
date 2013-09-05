/*
 * Filename: RouteAnalyser.java
 * Copyright:ICT (c) 2012-10-15
 * Description: 分析flow路径的类
 * Author: 25hours
 */
package ict.analyser.analysis;

import ict.analyser.common.Vertex;
import ict.analyser.database.DBWriter;
import ict.analyser.flow.Flow;
import ict.analyser.flow.Path;
import ict.analyser.flow.TrafficLink;
import ict.analyser.netflow.Netflow;
import ict.analyser.ospftopo.Link;
import ict.analyser.ospftopo.OspfRouter;
import ict.analyser.ospftopo.OspfTopo;
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
 * 用于分析flow路径的类
 * 
 * @author 25hours
 * @version 1.0, 2012-10-15
 */
public class OspfAnalyser implements Runnable {
	private long period = 0;// 周期id
	private boolean isPreCal = false;
	private boolean completed = false;
	private OspfTopo topo = null;// 保存当前AS拓扑结构等数据
	private Lock flowLock = null;
	private Lock completeLock = null;
	private DBWriter dbWriter = null;
	private Condition completeCon = null;// 锁相关：设置等待唤醒，相当于wait/notify
	private List<Netflow> netflows = null;// flow接收模块分析并聚合后得到的报文对象列表
	private RouteAnalyser processer = null;
	private ArrayList<Flow> allFlowRoute = null;// 全部flow的路径
	private HashMap<Integer, TrafficLink> mapLidTlink = null;// link id ——
	private Logger logger = Logger.getLogger(OspfAnalyser.class.getName());// 注册一个logger

	/**
	 * 重载构造函数
	 * 
	 * @param mainProcesser
	 */
	public OspfAnalyser(RouteAnalyser processer, boolean isPrecal) {
		this.isPreCal = isPrecal;
		this.processer = processer;
		this.period = processer.getPeriod();
		this.topo = processer.getOspfTopo();

		if (!isPrecal) { // 如果是计算流量路径需要额外初始化的变量
			this.dbWriter = new DBWriter();
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
		long srcAS = 0;
		long dstAS = 0;
		int direction = 0;// 记录flow种类，internal:1,inbound:2,outbound:3,transit:4
		long srcRouterId = 0;
		long dstRouterId = 0;
		long srcInterface = 0;
		long dstInterface = 0;
		long[] idInter = null;
		long topoAS = this.topo.getAsNumber();
		int flowCount = this.netflows.size();// 得到聚合后的netflow列表的条目总数

		Path path = null;
		Netflow netflow = null;// 临时变量
		Object[] result = new Object[3];
		ArrayList<Object[]> dstIdMetric = new ArrayList<Object[]>();// 保存目的设备id——metric映射，当是inbound和internal时，metric是0，因为目的设备id唯一，其他清空这里保存的是asbr的id——所宣告metric映射，这里为了计算接口统一而设计

		for (int i = 0; i < flowCount; i++) { // 开始遍历，逐条分析路径
			// 重置临时变量
			path = null;
			direction = 0;// 记录flow种类，internal:1,inbound:2,outbound:3,transit:4
			srcRouterId = 0;
			dstRouterId = 0;
			srcInterface = 0;
			dstInterface = 0;
			dstIdMetric.clear();// 清空map

			// 开始分析
			netflow = this.netflows.get(i);// 取得一条流
			srcAS = netflow.getSrcAs();// 源as号
			dstAS = netflow.getDstAs();// 目的as号

			if ((srcAS == 0 && dstAS == 0)
					|| (srcAS == topoAS && dstAS == topoAS)) {// 如果as都是0
																// 或者都等于拓扑文件中的as
																// 则为域内流量
				// 如果源和目的设备所在的as号和当前as号相同，是域内flow
				direction = Flow.INTERNAL;// 标记为inbound
				idInter = getRId(netflow.getSrcAddr(), netflow.getSrcMask());

				if (idInter == null) {
					// 这里添加源是另一个as的asbr接口发出的情况,这种情况下 源和目的as号都是0
					idInter = processInterAsFlow(netflow);

					if (idInter == null) {
						netflow.getDetail();
						logger.warning("internal flow !! idInter for"
								+ IPTranslator.calLongToIp(netflow.getSrcAddr())
								+ " can't be found!");
						System.out.println();
						continue;
					}
				}

				srcRouterId = idInter[0];
				srcInterface = idInter[1];

				if (srcRouterId == 0 || srcInterface == 0) {// 合法性检验
					netflow.getDetail();
					logger.warning("internal flow! router id for"
							+ IPTranslator.calLongToIp(netflow.getSrcAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}

				idInter = getRId(netflow.getDstAddr(), netflow.getDstMask());

				if (idInter == null) {
					netflow.getDetail();
					logger.warning("internal flow!!idInter for"
							+ IPTranslator.calLongToIp(netflow.getDstAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}

				dstRouterId = idInter[0];
				dstInterface = idInter[1];

				if (dstRouterId == 0 || dstInterface == 0) {// 合法性检验
					netflow.getDetail();
					logger.warning("internal flow! router id for"
							+ IPTranslator.calLongToIp(netflow.getDstAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}

				if (srcRouterId == dstRouterId) {// 如果源和目的设备id相同
					netflow.getDetail();
					logger.warning("src router id is same with dst router id!"
							+ "  "
							+ IPTranslator.calLongToIp(netflow.getSrcAddr())
							+ "  "
							+ IPTranslator.calLongToIp(netflow.getDstAddr()));
					path = new Path();
					path.setTotalCost(0);
					path.setSrcInterface(srcInterface);
					path.setDstInterface(dstInterface);
					path.setSrcRouter(srcRouterId);
				} else {
					logger.info("internal!! src router id:"
							+ IPTranslator.calLongToIp(srcRouterId)
							+ "   dst router id:"
							+ IPTranslator.calLongToIp(dstRouterId));

					path = this.processer.getPathByIds(srcRouterId + "_"
							+ dstRouterId);

					if (path == null) {
						logger.warning("path for src router id:"
								+ IPTranslator.calLongToIp(srcRouterId)
								+ "   dst router id:"
								+ IPTranslator.calLongToIp(dstRouterId)
								+ " not found!");
						continue;
					}
				}
			} else if ((srcAS == topoAS && dstAS != topoAS)
					|| (srcAS == 0 && dstAS != 0)) {// outboundflow

				direction = Flow.OUTBOUND;
				idInter = getRId(netflow.getSrcAddr(), netflow.getSrcMask());

				if (idInter == null) {
					netflow.getDetail();
					logger.info("outbound flow!! idInter for :"
							+ IPTranslator.calLongToIp(netflow.getSrcAddr()));
					System.out.println();
					continue;
				}

				srcRouterId = idInter[0];
				srcInterface = idInter[1];

				if (srcRouterId == 0 || srcInterface == 0) {// 合法性检验
					netflow.getDetail();
					logger.warning("outbound flow!! router id for"
							+ IPTranslator.calLongToIp(netflow.getSrcAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}

				// dstIdMetric = this.topo.getAsbrId(netflow.getDstAddr(),
				// netflow.getDstMask()); //
				// 根据目的设备ip和mask查找所有宣告所这个目的设备的asbr的id——metric的映射
				// 这里添加根据bgp信息获得目的路由器id函数！！！和接口

				if (dstRouterId == 0) {// 如果没有找到，提示出错，分析下一条
					netflow.getDetail();
					logger.warning("outbound flow!!destionation router id for"
							+ IPTranslator.calLongToIp(netflow.getDstAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}

				path = this.processer.getPathByIds(srcRouterId + "_"
						+ dstRouterId);

				if (path == null) {
					logger.warning("path for src router id:"
							+ IPTranslator.calLongToIp(srcRouterId)
							+ "   dst router id:"
							+ IPTranslator.calLongToIp(dstRouterId)
							+ " not found!");
					continue;
				}

			} else if ((srcAS != topoAS && dstAS == topoAS)
					|| (srcAS != 0 && dstAS == 0)) {// inboundflow

				direction = Flow.INBOUND;
				idInter = getRId(netflow.getDstAddr(), netflow.getDstMask());

				if (idInter == null) {
					netflow.getDetail();
					logger.warning("inbound flow!!idInter for"
							+ IPTranslator.calLongToIp(netflow.getDstAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}

				dstRouterId = idInter[0];
				dstInterface = idInter[1];

				if (dstRouterId == 0 || dstInterface == 0) {
					netflow.getDetail();
					logger.warning("inbound!!router id for"
							+ IPTranslator.calLongToIp(netflow.getDstAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}

				// 铺过域间流量并且返回asbr的id
				idInter = processInterAsFlow(netflow);

				if (idInter == null) {
					netflow.getDetail();
					logger.warning("inbound!!router id for"
							+ IPTranslator.calLongToIp(netflow.getSrcAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}

				srcRouterId = idInter[0];
				srcInterface = idInter[1];

				if (srcRouterId == 0) {// 合法性检验
					netflow.getDetail();
					logger.warning("inbound flow!!router id for"
							+ IPTranslator.calLongToIp(netflow.getSrcAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}

				if (srcRouterId == dstRouterId) {// 如果源和目的设备id相同
					netflow.getDetail();
					if (this.topo.getAsbrIds().contains(srcRouterId)) {
						logger.info("dst is border router! add flow to inter as link!!! src inter:"
								+ IPTranslator.calLongToIp(srcInterface)
								+ "  dst inter:"
								+ IPTranslator.calLongToIp(dstInterface));
						path = new Path();
						path.setTotalCost(0);
						path.setSrcRouter(srcRouterId);
						path.setSrcInterface(srcInterface);
						path.setDstInterface(dstInterface);
					}
				}

				if (path == null) {
					netflow.getDetail();
					logger.info("inbound!! src router id:"
							+ IPTranslator.calLongToIp(srcRouterId)
							+ "   dst router id:"
							+ IPTranslator.calLongToIp(dstRouterId));

					path = this.processer.getPathByIds(srcRouterId + "_"
							+ dstRouterId);

					if (path == null) {
						logger.warning("path for src router id:"
								+ IPTranslator.calLongToIp(srcRouterId)
								+ "   dst router id:"
								+ IPTranslator.calLongToIp(dstRouterId)
								+ " not found!");
						continue;
					}
				}

			} else {// transitflow
				direction = Flow.TRANSIT;

				// 铺域间流量并且返回router id
				idInter = processInterAsFlow(netflow);

				if (idInter == null) {
					netflow.getDetail();
					logger.warning("transit!!!router id for"
							+ IPTranslator.calLongToIp(netflow.getSrcAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}
				srcRouterId = idInter[0];
				srcInterface = idInter[1];// 20130606

				if (srcRouterId == 0) {// 合法性检验
					netflow.getDetail();
					logger.warning("transit!!!router id for"
							+ IPTranslator.calLongToIp(netflow.getSrcAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}

				// 查找netflow所经过的asbr id，从AS出口的
				dstIdMetric = topo.getAsbrId(netflow.getDstAddr(),
						netflow.getDstMask()); // 根据目的设备ip和mask查找所有宣告所这个目的设备的asbr的id——metric的映射

				if (dstIdMetric.size() == 0) {// 如果没有找到，提示出错，分析下一条
					netflow.getDetail();
					logger.warning("transit!!!destionation router id for"
							+ IPTranslator.calLongToIp(netflow.getDstAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}

				path = (Path) result[0];
				dstRouterId = (Long) result[1];
				// forwarding = (Integer) result[2];

			}// end of else

			if (path == null) {
				logger.warning("cannot find path for src id: "
						+ IPTranslator.calLongToIp(srcRouterId) + "   dst id:"
						+ IPTranslator.calLongToIp(dstRouterId));
				System.out
						.println("*********************************************\n");
				continue;
			}

			if (path.getTotalCost() == 0) {// 如果路径cost为0，则源和目的路由器相同
				path.setSrcRouter(srcRouterId);
				path.setDstRouterId(dstRouterId);
			}

			System.out.println("result path:" + path.getPathInIpFormat());
			System.out
					.println("*********************************************\n");
			// this.foundPath.put(srcRouter + "_" + dstRouter, path);
			this.processer.insertFoundPath(srcRouterId + "_" + dstRouterId,
					path);// 将路径加入成功路径缓存中

			// 分别设置path的源和目的前缀
			path.setSrcInterface(srcInterface);
			path.setDstInterface(dstInterface);
			// 插入流量
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
	 * 
	 * @param netflow
	 * @param syn
	 *            如果为true 则代表源为另一个as的边界路由器ip的特殊情况
	 * @return
	 */
	private long[] processInterAsFlow(Netflow netflow) {
		Object[] idLinkid = null;

		idLinkid = this.topo.getLinkidByIpInput(netflow.getRouterIP(),
				netflow.getInput());

		if (idLinkid == null) {
			logger.warning("can not find border router for :"
					+ IPTranslator.calLongToIp(netflow.getRouterIP()));
			return null;
		}

		int linkid = (Integer) idLinkid[1];

		if (linkid != 0) {
			logger.warning("add flow to border link!");
			setMapLidTraffic(linkid, netflow.getdOctets(), netflow.getDstPort());// 将边界链路id——flow加入映射中
		}

		long[] result = new long[2];
		result[0] = (Long) idLinkid[0];// 放路由器id
		result[1] = (Long) idLinkid[2];// 放路由器接口ip地址

		return result;
	}

	private long[] getRId(long ip, byte mask) {
		// 这里打了个补丁，如果netflow中的源ip或者目的ip是路由器的接口ip，那么先根据ip地址定位到路由器
		long[] routerId = this.topo.getRouterInterByIp(ip, mask);

		if (routerId == null) {
			// System.out.println("get router id by prefix:"
			// + IPTranslator.calLongToIp(ip));
			routerId = this.topo.getRouterIdByPrefix(ip, mask);// 根据源ip，mask获得源设备id
			// if (routerId != null)
			// System.out.println("found!!! prefix:"
			// + IPTranslator.calLongToIp(ip) + "  rid:"
			// + IPTranslator.calLongToIp(routerId[0]));
		}

		return routerId;
	}

	/**
	 * 写入数据库
	 */
	private void writeToDB() {
		this.flowLock.lock();
		this.dbWriter.writeToDB(this.allFlowRoute);
		this.flowLock.unlock();
		logger.info("write to db done!");
	}

	public void SPFCompute(long srcId) {// 已改
		if (srcId == -1) {
			logger.warning("src router id is invalid!");
			return;
		}

		OspfRouter srcRouter = this.topo.getRouterById(srcId);

		if (srcRouter == null) {
			logger.warning("cannot find router for id:"
					+ IPTranslator.calLongToIp(srcId));
			return;
		}

		// 临时变量
		long neighborId = 0;// 邻居设备id
		Vertex candidate = null;// 一次循环中从candidate集合中选中的
		Link neighborLink = null;// 链路对象
		OspfRouter router = null;// 路由器对象
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
	private Vertex getMinMetricId(HashMap<Long, Vertex> candidates) { // 已改
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
		long bytes = netflow.getdOctets();
		int linkId = 0;
		// System.out.println("path link size:"+size+"  "+path.getPathInIpFormat());
		for (int i = 0; i < size; i++) {
			link = links.get(i);
			// link.setTotalBytes(bytes);
			linkId = link.getLinkId();
			setMapLidTraffic(linkId, bytes, netflow.getDstPort());
		}
		Flow flow = new Flow(this.period, netflow, path, direction);
		this.allFlowRoute.add(flow);
	}

	// /**
	// * 判断flow大小是不是前topN的，如果是 ，加入topNflow列表中,这里可以考虑用最小堆做
	// *
	// * @param bytes
	// * 一条流的大小
	// * @return 返回是否加入topN条流里面
	// */
	// public boolean isInTopN(long bytes) {
	// int size = this.topNBytes.size();// 得到保存前topN条flow最大的flow列表
	// int position = (size == 0) ? size : (size - 1);// 位置指针，先置为列表最末尾
	//
	// for (int i = size - 1; i >= 0; i--) {// 从后向前遍历列表
	// if (bytes >= this.topNBytes.get(i)) {// 如果当前flow大小大于列表中这个位置的flow
	// position = i;// 指针标记位置
	// } else {
	// break;// 否则退出
	// }
	// }
	//
	// this.topNBytes.add(position, bytes);// 加入列表相应位置中
	//
	// if (position <= (size - 1)) {// 如果插入了，而且链表长度已经等于topN了
	// if (size == this.topN) {// 如果列表长度已经是topN了
	// this.topNBytes.remove(size);// 将第topn+1个删除
	// }
	// return true;
	// }
	// return false;
	// }

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
			link.addTraffic(bytes, port);
		} else {
			link = new TrafficLink(linkId);
			link.addTraffic(bytes, port);
			this.mapLidTlink.put(linkId, link);
		}
	}

	/**
	 * @return Returns the mapLinkIdBytes.
	 */
	public HashMap<Integer, TrafficLink> getMapLidTraffic() {
		return this.mapLidTlink;
	}

	public void setTopo(OspfTopo topo) {
		this.topo = topo;
	}

	public void setNetflow(List<Netflow> netflows) {
		this.netflows = netflows;
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
}
