/*
 * Filename: RouteAnalyser.java
 * Copyright:ICT (c) 2012-10-15
 * Description: 分析flow路径的类
 * Author: 25hours
 */
package ict.analyser.analysis;

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

	private Logger logger = Logger.getLogger(OspfAnalyser.class.getName());// 注册一个logger

	private int topN = 0;

	private long period = 0;

	private boolean completed = false;

	private Lock completeLock = null;

	private Lock flowLock = null;

	private Condition completeCon = null;// 锁相关：设置等待唤醒，相当于wait/notify

	private RouteAnalyser processer = null;

	private OspfTopo topo = null;// 保存当前AS拓扑结构等数据

	private boolean isPreCal = false;

	private DBWriter dbWriter = null;

	private List<Netflow> netflows = null;// flow接收模块分析并聚合后得到的报文对象列表

	private ArrayList<Flow> topNFlows = null;// top n条流路径,暂时不提供

	private ArrayList<Long> topNBytes = null;// topNflow的bytes

	private ArrayList<Flow> allFlowRoute = null;// 全部flow的路径

	private ArrayList<String> unfoundPath = null;// key是源路由器id+“_”+目的路由器id

	// private HashMap<String, Path> foundPath = null;// key是源路由器id+“_”+目的路由器id

	private HashMap<Long, SpfSnapShot> mapSrcSpf = null;
	// 优化：保存源为根的spf计算过程的快照，之所以是快照，是因为每次spf只计算到到特定目的id就停止，将这个瞬间保存，下一次在这个瞬间开始计算

	private HashMap<Long, ArrayList<Long>> mapPreCalId = null;// 下一个周期提前计算最短路径的源和目的对列表,这里设计成hash，源id——目的idlist映射，这样在下一次计算的时候可以在一个spf之内找到多个目的

	private HashMap<Integer, TrafficLink> mapLidTlink = null;// link id ——

	/**
	 * 重载构造函数
	 * 
	 * @param mainProcesser
	 */
	public OspfAnalyser(long pid, int topN, RouteAnalyser processer) {// 用topN
		this.period = pid; // 初始化
		this.topN = topN;
		this.isPreCal = false;
		this.flowLock = new ReentrantLock();
		this.completeLock = new ReentrantLock();
		this.completeCon = completeLock.newCondition();
		this.processer = processer;
		this.dbWriter = new DBWriter();
		this.topNFlows = new ArrayList<Flow>();
		this.topNBytes = new ArrayList<Long>();
		this.allFlowRoute = new ArrayList<Flow>();
		this.unfoundPath = new ArrayList<String>();
		// this.foundPath = new HashMap<String, Path>();
		// this.mapSrcSpf = new HashMap<String, SpfSnapShort>();
		this.mapLidTlink = new HashMap<Integer, TrafficLink>();
		this.mapPreCalId = new HashMap<Long, ArrayList<Long>>();
	}

	/**
	 * 重载构造函数
	 * 
	 * @param mainProcesser
	 */
	public OspfAnalyser(OspfTopo topo, RouteAnalyser processer) {
		this.topo = topo;
		this.isPreCal = true;
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
			System.out.println("prefre calculating");
			calTopoRoute();
			System.out.println("prefre calculating done!");
		} else { // 否则是计算flow路径
			System.out.println("flow route calculating");
			calFlowRoute();
		}

	}

	public void calTopoRoute() {
		if (this.mapPreCalId == null) {
			logger.info("mapPreCalId is illegal!");
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
			preCalShortest(srcId, dstIds);
		}

	}

	public void preCalShortest(long srcId, ArrayList<Long> dstIds) {

		OspfRouter srcRouter = this.topo.getRouterById(srcId);

		if (srcRouter == null) {
			return;
		}

		if (dstIds == null || dstIds.size() == 0) {
			return;
		}

		long dstId = 0;
		Path path = null;
		int size = dstIds.size();

		for (int i = 0; i < size; i++) {

			dstId = dstIds.get(i);

			if (dstId != 0) {
				path = SPFCompute(srcRouter, dstId);
			}

			if (path != null && path.getLinks().size() != 0) {
				processer.insertFoundPath(srcId + "_" + dstId, path);// 如果找到路径，加入成功路径缓存
			}
		}
	}

	public void calFlowRoute() {
		long srcAS = 0;
		long dstAS = 0;
		int direction = 0;// 记录flow种类，internal:1,inbound:2,outbound:3,transit:4
		long topoAS = this.topo.getAsNumber();
		int flowCount = this.netflows.size();// 得到聚合后的netflow列表的条目总数
		long srcRouterId = 0;
		long dstRouterId = 0;
		long srcInterface = 0;
		long dstInterface = 0;
		Path path = null;
		Netflow netflow = null;// 临时变量
		ArrayList<Object[]> dstIdMetric = new ArrayList<Object[]>();// 保存目的设备id——metric映射，当是inbound和internal时，metric是0，因为目的设备id唯一，其他清空这里保存的是asbr的id——所宣告metric映射，这里为了计算接口统一而设计
		Object[] result = new Object[3];
		long[] idInter = null;

		for (int i = 0; i < flowCount; i++) { // 开始遍历，逐条分析路径
			// 重置临时变量
			direction = 0;// 记录flow种类，internal:1,inbound:2,outbound:3,transit:4
			srcRouterId = 0;
			dstRouterId = 0;
			srcInterface = 0;
			dstInterface = 0;
			// forwarding = 0;
			dstIdMetric.clear();// 清空map
			path = null;

			// 开始分析
			netflow = this.netflows.get(i);// 取得一条流
			srcAS = netflow.getSrcAs();// 源as号
			dstAS = netflow.getDstAs();// 目的as号

			if ((srcAS == 0 && dstAS == 0)
					|| (srcAS == topoAS && dstAS == topoAS)) {// 如果as都是0
																// 或者都等于拓扑文件中的as
																// 则为域内流量
				// 如果源和目的设备所在的as号和当前as号相同，是域内flow
				direction = Flow.internal;// 标记为inbound

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

					System.out.println("  src inter:"
							+ IPTranslator.calLongToIp(srcInterface)
							+ "   dst inter:"
							+ IPTranslator.calLongToIp(dstInterface));

					// continue;
				} else {

					netflow.getDetail();
					System.out.println("internal!! src router id:"
							+ IPTranslator.calLongToIp(srcRouterId)
							+ "   dst router id:"
							+ IPTranslator.calLongToIp(dstRouterId));

					path = this.processer.getPathByIds(srcRouterId + "_"
							+ dstRouterId);

					if (path == null) {
						OspfRouter srcOspfRouter = this.topo
								.getRouterById(srcRouterId);

						if (srcOspfRouter == null) {
							continue;
						}

						path = SPFCompute(srcOspfRouter, dstRouterId);
					}
				}
			} else if ((srcAS == topoAS && dstAS != topoAS)
					|| (srcAS == 0 && dstAS != 0)) {// outboundflow

				direction = Flow.outbound;

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

				dstIdMetric = this.topo.getAsbrId(netflow.getDstAddr(),
						netflow.getDstMask()); // 根据目的设备ip和mask查找所有宣告所这个目的设备的asbr的id——metric的映射

				if (dstIdMetric.size() == 0) {// 如果没有找到，提示出错，分析下一条
					netflow.getDetail();
					logger.warning("outbound flow!!destionation router id for"
							+ IPTranslator.calLongToIp(netflow.getDstAddr())
							+ " can't be found!");
					System.out.println();
					continue;
				}

				// System.out.println("dstId metric size:" +
				// dstIdMetric.size());
				netflow.getDetail();
				for (int j = 0; j < dstIdMetric.size(); j++) {
					System.out.println("outbound!! src router id:"
							+ IPTranslator.calLongToIp(srcRouterId)
							+ "   dst id :"
							+ IPTranslator.calLongToIp((Long) dstIdMetric
									.get(j)[0]) + " metric :"
							+ dstIdMetric.get(j)[1]);

				}

				result = computeMultiDstPath(srcRouterId, dstIdMetric, netflow,
						direction);

				if (result == null) {
					continue;
				}

				path = (Path) result[0];
				dstRouterId = (Long) result[1];
				// forwarding = (Integer) result[2];

			} else if ((srcAS != topoAS && dstAS == topoAS)
					|| (srcAS != 0 && dstAS == 0)) {// inboundflow

				direction = Flow.inbound;
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

						System.out
								.println("dst is border router! add flow to inter as link!!! src inter:"
										+ IPTranslator
												.calLongToIp(srcInterface)
										+ "  dst inter:"
										+ IPTranslator
												.calLongToIp(dstInterface));
						path = new Path();
						path.setTotalCost(0);
						path.setSrcRouter(srcRouterId);
						path.setSrcInterface(srcInterface);
						path.setDstInterface(dstInterface);

					}
				}

				if (path == null) {
					netflow.getDetail();
					System.out.println("inbound!! src router id:"
							+ IPTranslator.calLongToIp(srcRouterId)
							+ "   dst router id:"
							+ IPTranslator.calLongToIp(dstRouterId));

					path = this.processer.getPathByIds(srcRouterId + "_"
							+ dstRouterId);

					if (path == null) {
						OspfRouter srcOspfRouter = this.topo
								.getRouterById(srcRouterId);

						if (srcOspfRouter == null) {
							continue;
						}

						path = SPFCompute(srcOspfRouter, dstRouterId);
					}
				}

			} else {// transitflow

				direction = Flow.transit;

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

				netflow.getDetail();
				for (int j = 0; j < dstIdMetric.size(); j++) {
					System.out.println("transit!! src router id:"
							+ IPTranslator.calLongToIp(srcRouterId)
							+ "   dst id :"
							+ IPTranslator.calLongToIp((Long) dstIdMetric
									.get(j)[0]) + " metric :"
							+ dstIdMetric.get(j)[1]);
				}

				result = computeMultiDstPath(srcRouterId, dstIdMetric, netflow,
						direction);

				if (result == null) {
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

			if (path.getTotalCost() == Integer.MAX_VALUE) {// 没找到路径，继续分析下一个netflow
				this.unfoundPath.add(srcRouterId + "_" + dstRouterId);// 加入到失败路径缓存中
				continue;
			} else if (path.getTotalCost() == 0) {// 如果路径cost为0，则源和目的路由器相同
				path.setSrcRouter(srcRouterId);
			}

			System.out.println("result path:" + path.getPathInIpFormat());
			System.out
					.println("*********************************************\n");
			// this.foundPath.put(srcRouter + "_" + dstRouter, path);
			this.processer.insertFoundPath(srcRouterId + "_" + dstRouterId,
					path);// 将路径加入成功路径缓存中

			// 将源和目的路由器存入列表，下一个周期提前计算最短路径的源和目的对列表
			addPreCal(srcRouterId, dstRouterId);

			// if (direction == Flow.inbound || direction == Flow.transit) {//
			// 如果flow类型是outbound或者transit的，计算下一跳路由器id，添加as级flow
			// // 这里的目的路由器id就是边界路由器id
			//
			// int linkId = this.topo.getInterAsLinkId(netflow.getRouterIP());
			//
			// if (linkId == 0) {
			// continue;
			// }
			//
			// setMapLinkIdBytes(linkId, netflow.getdOctets());//
			// 将边界链路id——flow加入映射中
			// }

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
	 * 
	 *
	 */
	private void writeToDB() {
		this.flowLock.lock();
		this.dbWriter.writeToDB(this.allFlowRoute);
		this.flowLock.unlock();
		System.out.println("write to db done!");
	}

	public Object[] computeMultiDstPath(long srcId, ArrayList<Object[]> dstMap,
			Netflow netflow, int direction) {

		OspfRouter srcRouter = this.topo.getRouterById(srcId);

		if (srcRouter == null) {
			return null;
		}

		Path path = null;
		int size = dstMap.size();
		int asbrToDst = 0;
		int isForwarding = 0;
		long dstId = 0;// 记录目的路由器id的临时变量

		Path bestPath = new Path();
		Object[] tempObj = new Object[3];
		Object[] result = new Object[3];
		int bestSum = Integer.MAX_VALUE;
		int sum = 0;

		for (int i = 0; i < size; i++) { // 遍历所有目的路由器
			tempObj = dstMap.get(i);
			dstId = (Long) tempObj[0];// 得到目的地址

			// if (srcId == dstId) {
			// continue;
			// }

			asbrToDst = (Integer) tempObj[1];// 得到asbr到目的路由器的metric
			isForwarding = (Integer) tempObj[2];// forwarding
												// address是否是0.0.0.0，是——0，否——1
			path = this.processer.getPathByIds(srcId + "_" + dstId);

			if (path == null) {
				path = SPFCompute(srcRouter, dstId);

				if (path == null) {
					logger.info("src:" + IPTranslator.calLongToIp(srcId)
							+ "  dst:" + IPTranslator.calLongToIp(dstId)
							+ "  path is null");
					continue;
				}
			}

			// System.out.println("src:" + IPTranslator.calLongToIp(srcId)
			// + "  dst:" + IPTranslator.calLongToIp(dstId) + "  path:"
			// + path.getPath() + " metric:" + path.getTotalCost());

			sum = path.getTotalCost() + asbrToDst;

			if (sum < bestSum) {// 如果这个目的路由器得到的path的总cost小于当前最小的，则更新最优路径
				bestPath = path;// 将当前路径赋值为最短路径
				bestSum = sum;
			}
		}

		if (dstId != srcId) {
			result[0] = bestPath;
			result[1] = dstId;
			result[2] = isForwarding;
			return result;
		}
		return null;
	}

	// public Path computeInternalPath(long srcId, long dstId,
	// Normal_Flow netflow, int direction) {
	//
	// if (this.unfoundPath.contains(srcId + "_" + dstId)) {// 如果源和目的对在失败路径缓存中
	// logger.info(IPTranslator.calLongToIp(srcId) + " to "
	// + IPTranslator.calLongToIp(dstId)
	// + " path cannto be found!");
	// return null;
	// }
	//
	// // path = this.foundPath.get(srcId + "_" + dstId);
	// Path path = this.processer.getPathByIds(srcId + "_" + dstId);//
	// 在成功路径缓存中查找源和目的id对
	//
	// if (path != null) {
	// System.out.println("path found! " + path.getPath());
	// return path;
	// }
	// // 缓存中没有，遍历目的路由器接口
	// OspfRouter dstRouter = this.topo.getRouterById(dstId);// 根据路由器id得到路由器对象
	//
	// if (dstRouter == null) {
	// return null;
	// }
	//
	// path = computeShortestPath(srcId, dstRouter, direction);
	// return path;
	// }

	// private boolean isFirst = true;
	//
	// public Path computeShortestPath(long srcId, OspfRouter dstRouter,
	// int direction) {
	//
	// OspfRouter srcRouter = this.topo.getRouterById(srcId);
	// // System.out.println("src router id :"
	// // + IPTranslator.calLongToIp(srcRouter.getRouterId()) + " areas:"
	// // + srcRouter.getAreas().toString());
	// ArrayList<String> srcArea = srcRouter.getAreas();
	// ArrayList<String> dstArea = dstRouter.getAreas();
	//
	// if (srcArea == null || dstArea == null) {
	// logger.info("src router or dst router dosen't belong to any areas!");
	// return null;
	// }
	// // System.out.println("src area before:" + srcArea.toString());
	//
	// @SuppressWarnings("unchecked")
	// ArrayList<String> a = (ArrayList<String>) srcArea.clone();
	//
	// srcArea.retainAll(dstArea);// 调用库函数得到两个集合的交集
	// // System.out.println("src area:" + srcArea.toString());
	// // System.out.println(srcRouter.getAreas().toString());
	// // System.out.println("a:" + a.toString());
	// String area = null;
	// Path tempPath = null;
	// Path bestPath = new Path();
	// int size = srcArea.size();
	// long dstId = dstRouter.getRouterId();
	//
	// if (size != 0) {// 如果两个设备属于同一个（或几个）area
	// System.out.println("same area:" + IPTranslator.calLongToIp(srcId)
	// + "  dst:" + IPTranslator.calLongToIp(dstId));
	//
	// for (int i = 0; i < size; i++) {
	// area = srcArea.get(i);
	// // tempPath = this.foundPath.get(srcId + "_" + dstId);
	// tempPath = this.processer.getPathByIds(srcId + "_" + dstId);
	//
	// if (tempPath == null) {
	// tempPath = SPFCompute(srcRouter, dstId, area);
	// }
	//
	// if (tempPath != null && tempPath.getLinks().size() != 0) {
	//
	// if (tempPath.getTotalCost() < bestPath.getTotalCost()) {
	// bestPath = tempPath;
	// }
	// }
	// }
	// } else {// 源和目的属于不同area
	// ArrayList<Object[]> abrSet = null;
	// srcArea = a;
	// Path partBest = new Path();
	//
	// ArrayList<Link> links = dstRouter.getLinks();
	// Link link = null;
	// int linkCount = links.size();// 得到链路总数
	// long ip = 0; // 保存ip地址的临时变量
	// long prefix = 0;
	//
	// for (int i = 0; i < linkCount; i++) {// 遍历目的路由器所有接口
	// link = links.get(i);
	// ip = link.getMyInterIp();
	// prefix = link.getPrefix();
	//
	// // System.out.println("area:" + srcArea.size() + "  dst area:"
	// // + dstArea.size());
	// if (this.isFirst) {// 标记是否是第一次调用本函数
	// // 是outbound或者transit的flow，“目的路由器”是调用函数找到的asbr的routerid，可以用lsa4
	// // 得到
	// this.isFirst = false;
	//
	// if (direction == Flow.outbound || direction == Flow.transit) {
	// abrSet = this.topo.getAbrSetById(dstId);
	// } else {
	// abrSet = this.topo.getAbrSet(prefix, ip);
	// // System.out.println("asbr:" + abrSet);
	// }
	// } else {
	// abrSet = this.topo.getAbrSet(prefix, ip);
	// }
	//
	// if (abrSet != null) {
	// break;
	// }
	//
	// }
	//
	// if (abrSet == null || abrSet.size() == 0) {
	// return null;
	// }
	//
	// size = abrSet.size();
	//
	// long routerId = 0;
	// long bestAbrId = 0;
	// int abrToDst = 0;
	// int partBestMetric = Integer.MAX_VALUE;
	// OspfRouter router = null;
	// Object[] tempObj = new Object[2];
	//
	// for (int i = 0; i < size; i++) {
	//
	// tempObj = abrSet.get(i);
	// routerId = (Long) tempObj[0];
	//
	// router = this.topo.getRouterById(routerId);
	//
	// if (router == null) {
	// continue;
	// }
	//
	// tempPath = computeShortestPath(srcId, router, direction);
	//
	// if (tempPath == null) {
	// // System.out.println("abr id:"
	// // + IPTranslator.calLongToIp(router.getRouterId())
	// // + " can't find path!");
	// continue;
	// }
	//
	// abrToDst = (Integer) tempObj[1];// 得到abr宣告的metric
	// System.out.println("abr id:"
	// + IPTranslator.calLongToIp(router.getRouterId())
	// + " metric :" + abrToDst);
	//
	// if ((tempPath.getTotalCost() + abrToDst) < (partBest
	// .getTotalCost() + partBestMetric)) {
	// partBest = tempPath;
	// partBestMetric = abrToDst;
	// bestAbrId = routerId;// 记录最优的abr id
	// }
	// }
	//
	// if (partBest.getLinks().size() == 0) {// 如果路径不存在 返回
	// return null;
	// }
	//
	// bestPath.appendPath(partBest);// 将部分最优链路拼接到最优链路
	// partBest = computeShortestPath(bestAbrId, dstRouter, direction);//
	// 计算从最优abrId
	// //
	// // if (partBest == null || partBest.getLinks().size() == 0) {//
	// // 如果路径不存在
	// // return null;
	// // }
	//
	// bestPath.appendPath(partBest);// 将若干部分的链路连接起来
	// }// end of else
	// return bestPath;
	// }

	// 这里有个优化，将每个源的每次spf算法结束后的最优结构和candidate保存起来，这样下一次计算时，如果源曾经计算过，
	// 但是之前计算过程中没计算到将本次的目的id加入到spf中（如果加过了，上面foundpath已经缓存直接能找到，无需再spf了）则得到本地保存上一次计算快照（spfmap
	// 和candidatemap）在此基础上继续计算

	public Path SPFCompute(OspfRouter srcRouter, long dstId) {// 已改
		if (srcRouter == null) {
			logger.info("src router is null!");
			return null;
		}

		long srcId = srcRouter.getRouterId();

		if (srcId == dstId) { // 如果源和目的id相同
			Path path = new Path();
			path.setTotalCost(0);
			return path;
		}

		// 临时变量
		int size = 0;
		int cost1 = 0;// 经过candidate节点的cost
		int cost2 = 0;// 不经过candidate的cost
		Link neighborLink = null;// 链路对象
		OspfRouter router = null;// 路由器对象
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
			link.setTotalBytes(bytes);
			linkId = link.getLinkId();
			setMapLidTraffic(linkId, bytes, netflow.getDstPort());
		}
		Flow flow = new Flow(this.period, netflow, path, direction);
		this.allFlowRoute.add(flow);
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
			link = new TrafficLink();
			link.addTraffic(bytes, port);
			this.mapLidTlink.put(linkId, link);
		}
	}

	public void addPreCal(long srcId, long dstId) {

		ArrayList<Long> dstIds = this.mapPreCalId.get(srcId);// 根据源id 找目的列表

		if (dstIds == null) {// 如果map中不存在，初始化并加入map
			dstIds = new ArrayList<Long>();
			dstIds.add(dstId);
			this.mapPreCalId.put(srcId, dstIds);
		} else {// 存在则直接加入目的
			dstIds.add(dstId);
		}

	}

	public void setPreCalMap(HashMap<Long, ArrayList<Long>> preCals) {
		if (preCals != null) {
			this.mapPreCalId = preCals;
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
