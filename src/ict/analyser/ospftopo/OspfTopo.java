/*
 * Filename: OspfTopo.java
 * Copyright: ICT (c) 2012-10-18
 * Description: 
 * Author: 25hours
 */
package ict.analyser.ospftopo;

import ict.analyser.flow.TrafficLink;
import ict.analyser.tools.IPTranslator;

import java.util.ArrayList;
import java.util.HashMap;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-18
 */
public class OspfTopo {

	private long periodId = 0;// 周期id，标记当前是第几周期

	private int asNumber = 0;// 拓扑所在AS号

	private ArrayList<InterAsLink> interAsLinks = null;

	private ArrayList<Long> asbrIds = null;

	private HashMap<Long, Long> mapASBRipId = null;// ASBR的接口ip(long)——设备id,来自TOPO文件中的“asbr”

	private HashMap<Long, OspfRouter> mapRidAsbr = null;// 拓扑中边界路由器id——路由器对象映射

	private HashMap<Long, Long> mapPrefixRouterId = null;// topo文件中stubs对应的
															// 拓扑中前缀与路由器id对应的映射,用于根据prefix查找路由器id，这里如果是网络中宣告prefix的路由器会有两个，但是这里只保存所有只有一个路由器宣告这个prefix的映射（优化）
	private HashMap<Long, Integer> mapASBRIpLinkid = null;// ASBR路由器开启监听netflow接口的ip地址和linkid
															// 对应映射
	private HashMap<Long, Long> mapIpRouterid = null;// 保存本AS内路由器ip——id映射

	private HashMap<Long, ArrayList<AsExternalLSA>> mapExternallsa = null;// 网络号（即网络前缀）——ArrayList<AsExternalLSA>映射，这个结构不放在area类原因是它设计到as级的路由器id查找

	private HashMap<Long, OspfRouter> mapRidRouter = null;// 路由器id——Router映射

	private HashMap<Integer, TrafficLink> mapLidTlink = null;// link id
																// ——TrafficLink

	public OspfTopo() {
		this.asbrIds = new ArrayList<Long>();
		this.mapASBRipId = new HashMap<Long, Long>();
		this.mapIpRouterid = new HashMap<Long, Long>();
		this.interAsLinks = new ArrayList<InterAsLink>();
		this.mapRidAsbr = new HashMap<Long, OspfRouter>();
		this.mapPrefixRouterId = new HashMap<Long, Long>();
		this.mapRidRouter = new HashMap<Long, OspfRouter>();
		this.mapLidTlink = new HashMap<Integer, TrafficLink>();
		this.mapASBRIpLinkid = new HashMap<Long, Integer>();
		this.mapExternallsa = new HashMap<Long, ArrayList<AsExternalLSA>>();
	}

	public void setMapASBRIpLinkId(long ip, int linkid) {
		if (ip != 0 && linkid != 0) {
			this.mapASBRIpLinkid.put(ip, linkid);
		}
	}

	public void setMapLidTraffic(int id) {
		if (id == 0) {
			return;
		}

		TrafficLink link = new TrafficLink(id);
		this.mapLidTlink.put(id, link);
	}

	/**
	 * @return Returns the mapLidTlink.
	 */
	public HashMap<Integer, TrafficLink> getMapLidTlink() {
		return mapLidTlink;
	}

	/**
	 * @return Returns the periodId.
	 */
	public long getPeriodId() {
		return periodId;
	}

	/**
	 * @return Returns the asNumber.
	 */
	public int getAsNumber() {
		return asNumber;
	}

	public void setMapAsbrIpRouterId(long ip, long id, int input, int linkid) {
		if (ip > 0 && id >= 0 && linkid > 0) {
			OspfRouter router = getRouterById(id);

			if (router != null) {
				router.setInputLinkid(input, linkid);
				this.mapASBRipId.put(ip, id);
				this.asbrIds.add(id);
			}
		}
	}

	public void setMapInputLinkid(long id, int input, int linkid) {
		OspfRouter router = this.getRouterById(id);

		if (router != null) {
			router.setInputLinkid(input, linkid);
		}
	}

	public ArrayList<Long> getAsbrIds() {
		return this.asbrIds;
	}

	/**
	 * @return Returns the mapASBRipId.
	 */
	public HashMap<Long, Long> getMapASBRipId() {
		return mapASBRipId;
	}

	/**
	 * 向保存prefix——asbr external lsa映射中添加条目
	 * 
	 * @param asExternalLSA
	 *            要添加的对象
	 */
	public void addAsExternalLSA(AsExternalLSA asExternalLSA) {
		// 如果参数中宣告的prefix已经在映射中了
		ArrayList<AsExternalLSA> tempList = this.mapExternallsa
				.get(asExternalLSA.getLinkStateId());
		if (tempList != null) {
			// 加入到列表中
			for (AsExternalLSA tempLsa : tempList) {
				// 这里是为了添加更新lsa准备的，新的lsa到了，就会删除，这里不会有性能问题，因为list size应该很小
				if (tempLsa.getAdvRouter() == asExternalLSA.getAdvRouter()) {
					tempList.remove(tempLsa);
					tempList.add(asExternalLSA);
					return;
				}
			}
			tempList.add(asExternalLSA);
		} else {
			// 否则新建一个列表，并加入映射中
			ArrayList<AsExternalLSA> lsaList = new ArrayList<AsExternalLSA>();
			lsaList.add(asExternalLSA);
			this.mapExternallsa.put(asExternalLSA.getLinkStateId(), lsaList);
		}
	}

	/**
	 * 根据更新信息从映射中删除对应entry
	 * 
	 * @param prefix
	 *            网络前缀
	 * @param routerId
	 *            设备id
	 */
	public void deleteExternalLSA(long prefix, long routerId) {
		ArrayList<AsExternalLSA> tempList = this.mapExternallsa.get(prefix);
		if (tempList != null) {
			// 遍历列表，找到与参数id相同的lsa，删除
			for (AsExternalLSA tempLsa : tempList) {
				if (tempLsa.getAdvRouter() == routerId) {
					tempList.remove(tempLsa);
				}
			}
		}
	}

	public OspfRouter getRouterById(long routerId) {

		if (routerId == 0) {
			System.out.println("router id is illegal in OspfAnalyser！");
			return null;
		}

		return this.mapRidRouter.get(routerId);
	}

	/**
	 * 根据ip地址和mask查找宣告这个prefix的asbr 的id——metric映射
	 * 
	 * 
	 * @param ip
	 * @param mask
	 * @return 宣告这个prefix的asbr 的id——metric映射
	 */
	public ArrayList<Object[]> getAsbrId(long ip, byte mask) {
		long dmask = IPTranslator.calByteToLong(mask);
		long prefix = ip & dmask; // 计算prefix
		ArrayList<Object[]> asbridMetric = new ArrayList<Object[]>();// 保存ASBR设备id——metric的临时变量

		ArrayList<AsExternalLSA> lsaList = null;// 保存找到的所有宣布能到这个prefix的lsa列表临时变量
		lsaList = this.mapExternallsa.get(prefix);// 在prefix——external
													// lsa映射中查找所有宣告这条prefix的lsa
		if (lsaList != null) {// 如果找到，根据e1，e2型进行处理
			asbridMetric = getMinMetricAsbr(lsaList);
		} else {// 如果没找到 循环移位查找
			int changeCount = 1;
			while (changeCount < 24) { // 循环移位截止：255.0.0.0
				changeCount++;
				dmask <<= 1;
				prefix = ip & dmask;// 计算新的prefix
				lsaList = this.mapExternallsa.get(prefix); // 在映射中查找对应external
															// lsa
				if (lsaList != null) {// 如果找到了external lsa列表
					asbridMetric = getMinMetricAsbr(lsaList);// 调用函数分析列表
					break;
				}
			}
		}// end of else

		return asbridMetric;
	}

	/**
	 * 根据getAsbrId函数找到的所有宣告过这个prefix的external lsa 查找最优lsa
	 * 
	 * @param lsaList
	 *            所有宣告过这个prefix的external lsa列表
	 * @return 最优lsa的设备id——metric映射
	 */
	public ArrayList<Object[]> getMinMetricAsbr(ArrayList<AsExternalLSA> lsaList) {

		int minMetric = Integer.MAX_VALUE;// 保存最小metric值
		int size = lsaList.size();// 保存列表大小

		AsExternalLSA templsa = null;// 临时变量，用于遍历过程
		ArrayList<Object[]> asbrIdMetric = new ArrayList<Object[]>();// 保存结果的临时变量
		ArrayList<AsExternalLSA> type1List = new ArrayList<AsExternalLSA>();// 保存宣告type1型lsa列表
		ArrayList<AsExternalLSA> type2List = new ArrayList<AsExternalLSA>();// 保存宣告type2型lsa列表,这里只装所有宣告metric相同的lsa

		for (int i = 0; i < size; i++) {// 循环开始
			templsa = lsaList.get(i);

			if (templsa.getExternalType() == 1) {// 如果是type1型lsa
				type1List.add(templsa); // 添加到列表中
			} else if (templsa.getExternalType() == 2) {// 如果是type2型lsa

				if (templsa.getMetric() < minMetric) { // 如果这个lsa宣告的metric小于记录的最小metric

					if (type2List.size() != 0) { // 如果列表中已经有表项了
						type2List.clear();// 清空列表
						type2List.add(templsa);// 将新的更小metric的表项加进去
					} else {// 否则直接加入列表中
						type2List.add(templsa);
					}

					minMetric = templsa.getMetric();// 将记录最小metric的变量重赋值

				} else if (templsa.getMetric() == minMetric) {// 这个lsa宣告的metric与记录最小的metric值相同，即两个type2的lsa5宣告的metric相同，都要保存，过后
					type2List.add(templsa);
				}
			}
		}// end of for

		size = type1List.size();// 用于记录type1型lsa列表长度
		Object[] tempArr = new Object[3];// 0——路由器id，1——所宣告的metric（在type2型
											// 的这里为0），3——forwarding
											// address是否为0，是——0，否——1
		if (size != 0) { // 如果存在
			int metric = 0;
			long routerId = 0;
			long forwardAddress = 0;

			for (int i = 0; i < size; i++) {
				templsa = type1List.get(i);
				forwardAddress = templsa.getForwardingAddress();// 获得转发地址

				if (forwardAddress == 0) {// 转发地址是ASBR
					routerId = templsa.getAdvRouter();

				} else {
					routerId = getRidByForwardAdd(forwardAddress);// 否则从保存AS之间链路的结构中找到forwarding
																	// address对应的路由器链路
				}

				metric = templsa.getMetric();// 获得metric，type1型为asbr到所宣告prefix的cost

				if (routerId != 0) {
					tempArr[0] = routerId;
					tempArr[1] = metric;
					tempArr[2] = (forwardAddress == 0) ? 0 : 1;
					asbrIdMetric.add(tempArr);
					tempArr = new Object[3];
				}
			}
		} else {

			size = type2List.size();
			long routerId = 0;
			long forwardAddress = 0;

			for (int i = 0; i < size; i++) {
				templsa = type2List.get(i);
				forwardAddress = templsa.getForwardingAddress();

				if (forwardAddress == 0) {// 转发地址是ASBR
					routerId = templsa.getAdvRouter();
				} else {
					routerId = getRidByForwardAdd(forwardAddress);// 否则从保存AS之间链路的结构中找到forwarding
																	// address对应的路由器链路
				}

				if (routerId != 0) {
					tempArr[0] = routerId;
					tempArr[1] = 0;// type2的lsa metric在这里都相同了 因此设为0
					tempArr[2] = (forwardAddress == 0) ? 0 : 1;
					asbrIdMetric.add(tempArr);
					tempArr = new Object[3];
				}
			}
		}
		return asbrIdMetric;
	}

	/**
	 * 
	 * 
	 * @param forwarding
	 * @return
	 */
	public long getRidByForwardAdd(long forwarding) {

		long ip = 0;
		// long mask = 0;
		InterAsLink link = null;
		int size = this.interAsLinks.size();

		for (int i = 0; i < size; i++) {
			link = this.interAsLinks.get(i);
			ip = link.getMyInterIp();
			// mask = link.getMask();

			if (ip == forwarding) {// 如果在同一网段
				return link.getNeighborBrId();// 返回邻居路由器id
			}
		}

		return 0;
	}

	public int getLinkIdByNextHopId(long nexthopId) {
		int size = this.interAsLinks.size();
		InterAsLink link = null;

		for (int i = 0; i < size; i++) {
			link = this.interAsLinks.get(i);

			if (nexthopId == link.getNeighborBrId()) {
				return link.getLinkId();// 返回链路id
			}
		}

		return 0;
	}

	/**
	 * 根据ip，mask查找对应路由器id
	 * 
	 * @param ip
	 * @param mask
	 * @return 路由器id
	 */
	@SuppressWarnings("unchecked")
	public long[] getRouterIdByPrefix(long ip, byte mask) {
		long result[] = new long[2];
		long dmask = IPTranslator.calByteToLong(mask);
		long prefix = ip & dmask;

		Object obj = this.mapPrefixRouterId.get(prefix);// 在前缀——路由器id映射中查找路由器id

		if (obj != null) {
			result[0] = (Long) obj;// 保存路由器id
			result[1] = prefix;// 保存路由器接口对应网段值

			return result;
		}

		obj = this.mapExternallsa.get(prefix);// 当是outbound
												// 和transit流量时，dstInterface无法确定，因此存入dstPrefix

		if (obj != null) {
			ArrayList<AsExternalLSA> arr = (ArrayList<AsExternalLSA>) obj;

			if (arr.size() > 0) {
				result[0] = arr.get(0).getAdvRouter();
				result[1] = prefix;
				return result;
			}
		}

		// 如果没找到这个prefix，循环移位重新计算prefix再查找
		int changeCount = 1;

		while (changeCount < 24) {
			changeCount++;
			dmask <<= 1;
			prefix = ip & dmask;// 根据ip和新的mask再计算prefix
			obj = this.mapPrefixRouterId.get(prefix);// 再查找

			if (obj != null) {// 如果找到了，返回
				result[0] = (Long) obj;
				result[1] = prefix;

				return result;
			}
		}

		return null;
	}

	/**
	 * @return Returns the interAsLinks.
	 */
	public ArrayList<InterAsLink> getInterAsLinks() {
		return interAsLinks;
	}

	/**
	 * @param interAsLinks
	 *            The interAsLinks to set.
	 */
	public void setInterAsLinks(InterAsLink link) {
		if (link != null) {
			this.interAsLinks.add(link);
		}
	}

	// public int getInterASLinkId(long rid, long ip, long mask) {
	//
	// int size = this.interAsLinks.size();
	//
	// if (size == 0) {
	// return 0;
	// }
	//
	// InterAsLink link = null;
	// ArrayList<InterAsLink> links = new ArrayList<InterAsLink>();
	//
	// // get all inter as links belong to this rid
	// for (int i = 0; i < size; i++) {
	// link = this.interAsLinks.get(i);
	//
	// if (rid == link.getMyBrId()) {
	// links.add(link);
	// }
	// }
	//
	// size = links.size();
	//
	// if (size == 0) {// if this rid has no inter as link
	// return 0;
	// }
	//
	// if (size == 1) {// if this rid has only one inter as link,return link id
	// return links.get(0).getLinkId();
	// }
	//
	// return 0;
	// }

	public int getInterAsLinkId(long ip) {
		int size = this.interAsLinks.size();
		long neighborIp = 0l;
		long mask = 0;

		InterAsLink link = null;

		for (int i = 0; i < size; i++) {
			link = this.interAsLinks.get(i);
			neighborIp = link.getMyInterIp();
			mask = link.getMask();

			if ((neighborIp & mask) == (ip & mask)) {
				return link.getLinkId();
			}
		}
		return 0;
	}

	/**
	 * @return Returns the mapPrefixRouterId.
	 */
	public HashMap<Long, Long> getMapPrefixRouterId() {
		return mapPrefixRouterId;
	}

	/**
	 * @param mapPrefixRouterId
	 *            The mapPrefixRouterId to set.
	 */
	public void setMapPrefixRouterId(long prefix, long routerId) {
		if (prefix != 0 && routerId != 0) {
			this.mapPrefixRouterId.put(prefix, routerId);
		}
	}

	/**
	 * @return Returns the mapExternallsa.
	 */
	public HashMap<Long, ArrayList<AsExternalLSA>> getMapExternallsa() {
		return mapExternallsa;
	}

	/**
	 * @param periodId
	 *            The periodId to set.
	 */
	public void setPeriodId(long periodId) {
		this.periodId = periodId;
	}

	/**
	 * @param asNumber
	 *            The asNumber to set.
	 */
	public void setAsNumber(int asNumber) {
		this.asNumber = asNumber;
	}

	/**
	 * 将边界链路添加到对应的路由器中（未用）
	 * 
	 * @param link
	 */
	public void addInterLinkToRouter(Link link) {

		if (link == null) {
			return;
		}

		long routerId = link.getMyId();
		OspfRouter router = getRouterById(routerId);

		if (router == null) {
			return;
		}

		router.setLink(link);
	}

	/**
	 * @return Returns the mapRidAsbr.
	 */
	public HashMap<Long, OspfRouter> getMapRidAsbr() {
		return mapRidAsbr;
	}

	/**
	 * @param mapRidAsbr
	 *            The mapRidAsbr to set.
	 */
	public void setMapRidAsbr(long routerId, OspfRouter router) {
		if (routerId != 0 && router != null) {
			this.mapRidAsbr.put(routerId, router);
		}
	}

	public void setRidRouter(long rid, OspfRouter router) {
		if (rid != 0 && router != null) {
			this.mapRidRouter.put(rid, router);
		}
	}

	public int getLinkIdByIp(long ip) {
		return this.mapASBRIpLinkid.get(ip);
	}

	/**
	 * @return Returns the mapIpRouterid.
	 */
	public HashMap<Long, Long> getMapIpRouterid() {
		return mapIpRouterid;
	}

	public long[] getRouterInterByIp(long ip, byte mask) {
		long[] result = new long[2];

		if (this.mapIpRouterid.get(ip) != null) {
			// long masklong = IPTranslator.calByteToLong(mask);
			result[0] = this.mapIpRouterid.get(ip);
			// result[1] = ip & masklong;//20130606 这里应保存接口ip而不是前缀信息
			result[1] = ip;
			return result;
		}
		return null;
	}

	/*
	 * 根据路由器id和ip得到该ip对应网段
	 */
	public long getPrefixOfRouter(long rid, long ip) {
		if (rid == 0 || ip == 0) {
			return 0;
		}

		OspfRouter router = this.mapRidRouter.get(rid);

		if (router != null) {
			return router.getPrefixByIp(ip);
		}

		return 0;
	}

	/**
	 * @param mapIpRouterid
	 *            The mapIpRouterid to set.
	 */
	public void setMapIpRouterid(long ip, long rid) {
		if (ip != 0 && rid != 0) {
			this.mapIpRouterid.put(ip, rid);
			// System.out.println("ip:" + IPTranslator.calLongToIp(ip) + "  id:"
			// + IPTranslator.calLongToIp(rid));
		}
	}

	public Object[] getLinkidByIpInput(long ip, int input) {
		Object[] result = null;
		Object rid = mapIpRouterid.get(ip);

		if (rid != null) {
			OspfRouter router = mapRidRouter.get((Long) rid);

			if (router != null) {
				int linkid = router.getLinkidByInput(input);
				result = new Object[3];
				result[0] = rid;// 路由器id
				result[1] = linkid;// 链路id
				// result[2] = router.getPrefixByLinkId(linkid); //错误！
				// 根据ip得到该ip所在网段
				// result[2] = getPrefixByLinkid(linkid);//20130606这里改成保存路由器接口ip
				result[2] = getIpByLinkid(linkid);
			} else {
				System.out.println("!!!!!!!!!!!!!!! router not found!!!!");

			}
		} else {
			System.out.println("!!!!!!!!!!!!!!! rid not found!!!!");
		}

		return result;
	}

	public long getPrefixByLinkid(int linkid) {
		int size = this.interAsLinks.size();
		InterAsLink link = null;

		for (int i = 0; i < size; i++) {
			link = this.interAsLinks.get(i);

			if (link.getLinkId() == linkid) {
				return link.getMask() & link.getMyInterIp();
			}
		}
		return 0;
	}

	public long getIpByLinkid(int linkid) {
		int size = this.interAsLinks.size();
		InterAsLink link = null;

		for (int i = 0; i < size; i++) {
			link = this.interAsLinks.get(i);

			if (link.getLinkId() == linkid) {
				return link.getMyInterIp();
			}
		}
		return 0;
	}

	public ArrayList<Long> getNeighborIpsOfInterLink() {
		InterAsLink link = null;
		int size = this.interAsLinks.size();
		ArrayList<Long> ips = new ArrayList<Long>();

		for (int i = 0; i < size; i++) {
			link = this.interAsLinks.get(i);

			if (link.getNeighborBrIp() != 0) {
				ips.add(link.getNeighborBrIp());
			}
		}
		return ips;
	}
}
