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
import ict.analyser.isistopo.Reachability;
import ict.analyser.netflow.Netflow;
import ict.analyser.ospftopo.Link;
import ict.analyser.tools.IPTranslator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-11-25
 */
public class IsisAnalyser extends Thread {
	private long period = 0;
	private IsisTopo topo = null;
	private Lock flowLock = null;
	private boolean isPreCal = false;
	private DBOperator dbWriter = null;
	private List<Long> routerIds = null;
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
	public IsisAnalyser(RouteAnalyser analyser, IsisTopo topo,
			boolean isPrecal, List<Netflow> netflows) {
		this.topo = topo;
		this.isPreCal = isPrecal;
		this.processer = analyser;
		this.period = processer.getPeriod();

		if (!isPrecal) { // 如果是计算流量路径需要额外初始化的变量
			this.netflows = netflows;
			this.dbWriter = new DBOperator();
			this.flowLock = new ReentrantLock();
			this.allFlowRoute = new ArrayList<Flow>();
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
		for (int i = 0, len = this.routerIds.size(); i < len; i++) {
			SPFCompute(this.routerIds.get(i));
		}
	}

	public void calFlowRoute() {
		if (this.topo.getNetworkType() == 1) {
			calL1Flow();
		} else {
			calL2Flow();
		}
	}

	boolean srcIn, dstIn;

	private void calL2Flow() {
		int resultType;
		Path path = null;
		Netflow netflow = null;// 临时变量
		long srcRouterId, dstRouterId;
		Object[] dstInfo;

		for (int i = 0, flowCount = this.netflows.size(); i < flowCount; i++) { // 开始遍历，逐条分析路径
			// 开始分析
			netflow = this.netflows.get(i);// 取得一条流

			if (netflow == null) {
				continue;
			}

			srcIn = true;
			dstIn = true;
			srcRouterId = getSrcId(netflow.getRouterIP(), netflow.getSrcAddr(),
					netflow.getSrcMask());

			if (srcRouterId == 0) {
				debug(netflow.getSrcAddr(), 0);
				continue;
			}

			// 定位目的路由器
			dstInfo = this.topo.getRidByPrefix(netflow.getDstAddr(),
					netflow.getDstMask(), Constant.LEVEL2);

			if (dstInfo == null) {
				debug(0, netflow.getDstAddr());
				continue;
			}

			resultType = (Integer) dstInfo[0];

			if (resultType == Constant.FOUND_IN_REACH) {// 在stub中
				dstIn = false;
			}

			dstRouterId = (Long) dstInfo[1];

			if (dstRouterId == 0 || dstRouterId == srcRouterId) {
				debug(0, netflow.getDstAddr());
				continue;
			}

			path = processer.getPathByIds(srcRouterId + "_" + dstRouterId);

			if (path == null) {
				debug(srcRouterId, dstRouterId);
				continue;
			}

			if (srcIn && dstIn) {
				this.processer.updateStatics(netflow, Constant.INTERNAL_FLOW);
			} else if (srcIn && !dstIn) {
				this.processer.updateStatics(netflow, Constant.OUTBOUND_FLOW);
			} else if (!srcIn && dstIn) {
				this.processer.updateStatics(netflow, Constant.INBOUND_FLOW);
			}
			debug(path);
			insertFlow(netflow, path);
		}// end of for
			// 所有流量都分析完了

		if (this.allFlowRoute.size() > 0) {
			writeToDB();// 存入数据库
		}
	}

	public void calL1Flow() {
		int resultType;
		Path path = null;
		Netflow netflow = null;// 临时变量
		long srcRouterId = 0, dstRouterId = 0;
		Object[] dstInfo;

		for (int i = 0, flowCount = this.netflows.size(); i < flowCount; i++) { // 开始遍历，逐条分析路径
			netflow = this.netflows.get(i);// 取得一条流

			if (netflow == null) {
				continue;
			}

			srcIn = true;
			dstIn = true;
			srcRouterId = getSrcId(netflow.getRouterIP(), netflow.getSrcAddr(),
					netflow.getSrcMask());

			if (srcRouterId == 0) {
				debug(netflow.getSrcAddr(), 0);
				continue;
			}

			// 定位目的路由器
			dstInfo = this.topo.getRidByPrefix(netflow.getDstAddr(),
					netflow.getDstMask(), Constant.LEVEL1);
			resultType = (Integer) dstInfo[0];

			if (resultType == Constant.IN_STUB) {
				dstRouterId = (Long) dstInfo[1];
				path = processer.getPathByIds(srcRouterId + "_" + dstRouterId);
			} else if (resultType == Constant.FOUND_IN_REACH) {
				// 都配置重分发的情况要计算源到l1/l2路由器距离
				// 与重分发报文中宣告的metric之和最小的路径（即整条链路metric最短路径）
				@SuppressWarnings("unchecked")
				LinkedList<Reachability> reaches = (LinkedList<Reachability>) dstInfo[1];
				Iterator<Reachability> iterator = reaches.iterator();
				int min = Integer.MAX_VALUE;

				while (iterator.hasNext()) {
					Reachability tmp = iterator.next();
					Path tmpPath = processer.getPathByIds(srcRouterId + "_"
							+ tmp.getSysId());

					if (path == null) {
						continue;
					}

					int cost = path.getTotalCost() + tmp.getMetric();

					if (cost < min) {
						min = cost;
						dstRouterId = tmp.getSysId();
						path = tmpPath;
					}
				}
			} else {
				// 如果没有渗透 则得到所有l1/l2路由器id列表，取源到这个id列表之间的最短路径
				@SuppressWarnings("unchecked")
				LinkedList<Long> brIds = (LinkedList<Long>) dstInfo[1];

				Iterator<Long> iter = brIds.iterator();
				int min = Integer.MAX_VALUE;
				Path tmpPath;
				long tmpId;

				while (iter.hasNext()) {
					tmpId = iter.next();
					tmpPath = this.processer.getPathByIds(srcRouterId + "_"
							+ tmpId);

					if (tmpPath != null && tmpPath.getTotalCost() < min) {
						min = path.getTotalCost();
						dstRouterId = tmpId;
						path = tmpPath;
					}
				}

			}

			if (path == null || srcRouterId == dstRouterId) {
				debug(srcRouterId, dstRouterId);
				continue;
			}

			if (srcIn && dstIn) {
				this.processer.updateStatics(netflow, Constant.INTERNAL_FLOW);
			} else if (srcIn && !dstIn) {
				this.processer.updateStatics(netflow, Constant.OUTBOUND_FLOW);
			} else if (!srcIn && dstIn) {
				this.processer.updateStatics(netflow, Constant.INBOUND_FLOW);
			}

			debug(path);
			insertFlow(netflow, path);
		}// end of for

		if (this.allFlowRoute.size() > 0) {
			writeToDB();// 存入数据库
		}
	}

	public long getSrcId(long routerIp, long ip, byte mask) {
		long rid = this.topo.getSrcRidByPrefix(ip, mask);

		if (rid != 0) {
			return rid;
		}

		srcIn = false;
		return this.topo.getBrIdByIp(routerIp);// 根据路由器ip判断进入这个Area的l1/l2路由器
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

	public void insertFlow(Netflow netflow, Path path) {
		ArrayList<Link> links = path.getLinks();
		Link link = null;
		int size = links.size();
		int linkId = 0;

		for (int i = 0; i < size; i++) {
			link = links.get(i);
			linkId = link.getLinkId();
			setMapLidTraffic(linkId, netflow.getdOctets(), netflow.getDstPort());
		}
		Flow flow = new Flow(netflow, path);
		this.allFlowRoute.add(flow);
	}

	/**
	 * @param mapLinkIdBytes
	 *            The mapLinkIdBytes to set. 如果端口号为0，则算other类流量
	 */
	public void setMapLidTraffic(int linkId, long bytes, int port) {
		if (linkId == 0 || bytes == 0) {
			return;
		}

		String protocal = this.processer.getProtocalByPort(port);// 根据端口号获得协议名字

		// 如果这个端口号没找到相应协议名，记为“other”类型
		if (protocal == null) {
			protocal = "other";
		}

		TrafficLink link = this.mapLidTlink.get(linkId);

		if (link != null) {
			link.addTraffic(protocal, bytes);
		} else {
			link = new TrafficLink(linkId);
			link.setMapProtocalBytes(this.processer.getMapProtocalBytes());// 用协议名——byte映射初始化trafficlink中的映射
			link.addTraffic(protocal, bytes);
			this.mapLidTlink.put(linkId, link);
		}
	}

	private void writeToDB() {
		this.flowLock.lock();
		this.dbWriter.writeFlowToDB(this.period, this.allFlowRoute);
		this.flowLock.unlock();
		System.out.println("wrote to db done!!");
	}

	public void setRouterIdsToPrecal(List<Long> routerIds) {
		this.routerIds = routerIds;
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

	private void debug(Path path) {
		// 以下为调试输出
		ArrayList<Long> idsOnPath = path.getPathInIsisIpFormat();
		int size = idsOnPath.size();
		String temp = "result path:";

		for (int x = 0; x < size; x++) {
			temp += " | " + this.topo.getMapLongStrId().get(idsOnPath.get(x));
		}

		System.out.println(temp);
		System.out
				.println("***************************************************\n");
		// 调试输出结束
	}

	private void debug(long srcIp, long dstIp) {
		if (srcIp != 0 && dstIp != 0) {
			logger.warning("cannot find path for:"
					+ IPTranslator.calLongToIp(srcIp) + " "
					+ IPTranslator.calLongToIp(dstIp));
		} else {
			if (srcIp != 0) {
				logger.warning("cannot find prefix for:"
						+ IPTranslator.calLongToIp(srcIp));
			} else {
				logger.warning("cannot find prefix for:"
						+ IPTranslator.calLongToIp(dstIp));
			}
		}
		System.out
				.println("***************************************************\n");
	}

}
