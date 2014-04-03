/*
 * Filename: RouteAnalyser.java
 * Copyright:ICT (c) 2012-10-15
 * Description: 分析flow路径的类
 * Author: 25hours
 */
package ict.analyser.analysis;

import ict.analyser.common.Constant;
import ict.analyser.common.Vertex;
import ict.analyser.database.DBOperator;
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
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

/**
 * 用于分析flow路径的类
 * 
 * @author 25hours
 * @version 1.0, 2012-10-15
 */
public class OspfAnalyser extends Thread {
	private long period = 0;// 周期id
	private boolean isPreCal = false;
	private OspfTopo topo = null;// 保存当前AS拓扑结构等数据
	private Lock flowLock = null;
	private DBOperator dbWriter = null;
	private List<Long> routerIds = null;// 需要提前分析的路由器id列表
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
	public OspfAnalyser(RouteAnalyser analyser, OspfTopo topo,
			boolean isPrecal, List<Netflow> netflows) {
		this.topo = topo;
		this.isPreCal = isPrecal;
		this.processer = analyser;
		this.period = analyser.getPeriod();

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
			// logger.info("prefre calculating");
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

	boolean srcIn, dstIn;

	public void calFlowRoute() {
		long srcRouterId = 0, dstRouterId = 0;
		Netflow netflow = null;// 临时变量

		for (int i = 0, flowCount = this.netflows.size(); i < flowCount; i++) { // 开始遍历，逐条分析路径
			netflow = this.netflows.get(i);// 取得一条流
			// 在确定流量特性时不能根据报文中的srcASdstAS确定，因为除了ASBR外的叶子节点是不知道流量AS信息的，直接在stub中查找
			if (netflow == null) {
				continue;
			}

			srcIn = true;
			dstIn = true;
			srcRouterId = getRId(netflow, Constant.SRC_ADDRESS);

			if (srcRouterId == 0) {
				debug(netflow.getSrcAddr(), 0);
				continue;
			}

			dstRouterId = getRId(netflow, Constant.DST_ADDRESS);
			// 根据前缀信息获得asbr id 同时铺完边界链路流量

			if (dstRouterId == 0) {
				debug(0, netflow.getDstAddr());
				return;
			}

			netflow.setSrcRouter(srcRouterId);
			netflow.setDstRouter(dstRouterId);

			Path path;

			if (srcRouterId == dstRouterId) {// 如果源和目的设备id相同 ,不处理
				debug(0, 0);
				continue;
			}

			path = this.processer.getPathByIds(srcRouterId + "_" + dstRouterId);

			if (path == null) { // 打印信息
				// debug(netflow.getSrcAddr(), netflow.getDstAddr());
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
			// 插入流量
			insertFlow(netflow, path);
		}// end of for
			// 所有流量都分析完了
		if (this.allFlowRoute.size() > 0) {
			writeToDB();// 存入数据库
		}
	}

	private long getRId(Netflow flow, boolean isSrcAddress) {
		// 这里打了个补丁，这样能保证网络中的所有流量都能被分析，而非只分析终端，如果netflow中的源ip或者目的ip是路由器的接口ip，那么先根据ip地址定位到路由器，这里包括每个路由器接口ip和边界路由器接口ip
		long ip = 0l;
		byte mask = 0;

		if (isSrcAddress == true) {
			ip = flow.getSrcAddr();
			mask = flow.getSrcMask();
		} else {
			ip = flow.getDstAddr();
			mask = flow.getDstMask();
		}

		long routerId = this.topo.getRouterInterByIp(ip);

		if (routerId != 0) {// 是路由器接口发出的流量
			return routerId;
		}

		routerId = this.topo.getRouterIdByPrefix(ip, mask);// 根据源ip，mask获得源设备id

		if (routerId != 0) {
			return routerId;
		}

		if (isSrcAddress == true) {
			this.srcIn = false;
			routerId = getAsbrIdByRouterIp(flow.getRouterIP());
		} else {
			this.dstIn = false;
			routerId = getAsbrIdByPrefix(ip, mask, flow.getdOctets(),
					flow.getDstPort());
		}

		return routerId;
	}

	private long getAsbrIdByRouterIp(long routerIp) {
		return this.topo.getAsbrRidByIp(routerIp);
	}

	private long getAsbrIdByPrefix(long ip, byte mask, long bytes, int port) {
		Object[] result = this.topo.getAsbrIdByPrefix(ip, mask);

		if (result == null) {
			return 0;
		}

		setMapLidTraffic((Integer) result[1], bytes, port);// 铺域间链路流量
		return (Long) result[0];// 返回边界路由器id
	}

	/**
	 * 写入数据库
	 */
	private void writeToDB() {
		this.flowLock.lock();
		this.dbWriter.writeFlowToDB(this.period, this.allFlowRoute);
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

	public void insertFlow(Netflow netflow, Path path) {
		ArrayList<Link> links = path.getLinks();
		Link link = null;
		int size = links.size();
		long bytes = netflow.getdOctets();
		int linkId = 0;

		for (int i = 0; i < size; i++) {
			link = links.get(i);
			linkId = link.getLinkId();
			setMapLidTraffic(linkId, bytes, netflow.getDstPort());
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

	private void debug(Path path) {
		System.out.println("result path:" + path.getPathInIpFormat());
		System.out.println("*********************************************\n");
	}

	//
	private void debug(long srcIp, long dstIp) {
		if (srcIp != 0 && dstIp != 0) {
			logger.warning("cannot find path for:"
					+ IPTranslator.calLongToIp(srcIp) + " "
					+ IPTranslator.calLongToIp(dstIp));
		} else {
			if (srcIp != 0) {
				logger.warning("cannot find prefix for:"
						+ IPTranslator.calLongToIp(srcIp));
				return;
			}
			if (dstIp != 0) {
				logger.warning("cannot find prefix for:"
						+ IPTranslator.calLongToIp(dstIp));
				return;
			}

			logger.warning("src router id is same with dst router id!");

		}
		System.out
				.println("***************************************************\n");
	}

}
