/*
 * Filename: OspfTopo.java
 * Copyright: ICT (c) 2012-10-18
 * Description: 
 * Author: 25hours
 */
package ict.analyser.ospftopo;

import ict.analyser.tools.IPTranslator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.logging.Logger;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-18
 */
public class OspfTopo {
	private int asNumber = 0;// 拓扑所在AS号
	private long periodId = 0;// 周期id，标记当前是第几周期
	private ArrayList<Long> asbrIds = null;// 保存全部边界路由器id
	private ArrayList<Integer> linkIds = null;// 保存全部链路id的数组
	private HashMap<Long, Long> mapIpRouterid = null;// 保存本AS内路由器ip——id映射
	private HashMap<Long, OspfRouter> mapRidAsbr = null;// 拓扑中边界路由器id——路由器对象映射
	private HashMap<Long, Long> mapPrefixRouterId = null;// topo文件中stubs对应的
	private HashMap<Long, Integer> mapASBRIpLinkid = null;// ASBR路由器开启监听netflow接口的ip地址和linkid
	private HashMap<Long, OspfRouter> mapRidRouter = null;// 路由器id——Router映射
	private HashMap<Long, BgpItem> mapPrefixBgpItem = null;// prefix和宣告这个prefix的bgp报文
	private HashMap<Long, InterAsLink> mapNextHopAsLink = null;// nexthop——边界链路对象映射
	private HashMap<Long, AsExternalLSA> mapPrefixExternalLsa = null;// 前缀——LSA5映射
	private Logger logger = Logger.getLogger(OspfTopo.class.getName());// 注册一个logger

	public OspfTopo(boolean initial) {
		if (!initial) {
			return;
		}

		this.asbrIds = new ArrayList<Long>();
		this.linkIds = new ArrayList<Integer>();
		this.mapIpRouterid = new HashMap<Long, Long>();
		this.mapRidAsbr = new HashMap<Long, OspfRouter>();
		this.mapPrefixRouterId = new HashMap<Long, Long>();
		this.mapRidRouter = new HashMap<Long, OspfRouter>();
		this.mapASBRIpLinkid = new HashMap<Long, Integer>();
		this.mapNextHopAsLink = new HashMap<Long, InterAsLink>();
		this.mapPrefixExternalLsa = new HashMap<Long, AsExternalLSA>();
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

		this.linkIds.add(id);
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

	public void setMapInputLinkid(long id, int input, int linkid) {
		OspfRouter router = this.getRouterById(id);

		if (router != null) {
			router.setInputLinkid(input, linkid);
		}
	}

	public ArrayList<Long> getAsbrIds() {
		return this.asbrIds;
	}

	public OspfRouter getRouterById(long routerId) {
		if (routerId == 0) {
			logger.warning("router id is illegal in OspfAnalyser！");
			return null;
		}

		return this.mapRidRouter.get(routerId);
	}

	/*
	 * 根据前缀查找bgp表返回宣告的边界路由器id
	 */
	public Object[] getAsbrIdByPrefix(long ip, byte mask) {
		long dmask = IPTranslator.calByteToLong(mask);
		long prefix = ip & dmask;

		// 如果没找到这个prefix，循环移位重新计算prefix再查找
		Object obj;
		long nextHop = 0;
		int changeCount = 0;

		while (changeCount < 24) {
			prefix = ip & dmask;// 根据ip和新的mask再计算prefix
			obj = this.mapPrefixBgpItem.get(prefix);// 查找BGP路由表

			if (obj != null) {
				BgpItem item = (BgpItem) obj;
				nextHop = item.getNextHop();
				InterAsLink link = this.mapNextHopAsLink.get(nextHop);

				if (link != null) {
					Object[] result = new Object[2];
					result[0] = link.getMyBrId();
					result[1] = link.getLinkId();
					return result;
				}
			}

			changeCount++;
			dmask <<= 1;
		}
		return null;
	}

	/*
	 * 根据发送路由器ip得到边界路由器id和接口
	 */
	public long getAsbrRidByIp(long ip) {
		if (ip <= 0) {
			return 0;
		}

		Object obj = this.mapIpRouterid.get(ip);

		if (obj == null) {
			logger.warning("cannot get rid of ip:"
					+ IPTranslator.calLongToIp(ip));
			return 0;
		}

		return (Long) obj;
	}

	/**
	 * 根据ip，mask查找对应路由器id
	 * 
	 * @param ip
	 * @param mask
	 * @return 路由器id
	 */
	public long getRouterIdByPrefix(long ip, byte mask) {
		long dmask = IPTranslator.calByteToLong(mask);
		long prefix = ip & dmask;

		Object obj;
		int changeCount = 1;

		while (changeCount < 24) {
			prefix = ip & dmask;// 根据ip和新的mask再计算prefix
			obj = this.mapPrefixRouterId.get(prefix);// 在prefix——id映射中查找

			if (obj != null) {// 如果找到了，返回
				return (Long) obj;
			}

			obj = this.mapPrefixExternalLsa.get(prefix);// 如果没找到在prefix——lsa5中再找一次

			if (obj != null) {// 如果找到了返回
				AsExternalLSA lsa = (AsExternalLSA) obj;
				return lsa.getAdvRouter();
			}
			changeCount++;
			dmask <<= 1;
		}

		return 0;
	}

	/**
	 * @return Returns the linkIds.
	 */
	public ArrayList<Integer> getLinkIds() {
		return linkIds;
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
	 * @return Returns the mapPrefixBgpItem.
	 */
	@SuppressWarnings("unchecked")
	public HashMap<Long, BgpItem> getMapPrefixBgpItem() {
		return (HashMap<Long, BgpItem>) mapPrefixBgpItem.clone();
	}

	/**
	 * @param mapPrefixBgpItem
	 *            The mapPrefixBgpItem to set.
	 */
	public void setMapPrefixBgpItem(HashMap<Long, BgpItem> mapPrefixBgpItem) {
		this.mapPrefixBgpItem = mapPrefixBgpItem;
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

	/**
	 * @return Returns the mapRidRouter.
	 */
	public HashMap<Long, OspfRouter> getMapRidRouter() {
		return mapRidRouter;
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

	public long getRouterInterByIp(long ip) {
		if (ip == 0) {
			return 0;
		}

		Object routerId = this.mapIpRouterid.get(ip);
		return (routerId == null) ? 0 : (Long) routerId;
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
		}
	}

	/**
	 * @param mapPrefixExternalLsa
	 *            The mapPrefixExternalLsa to set.
	 */
	public void setMapPrefixExternalLsa(
			HashMap<Long, AsExternalLSA> mapPrefixExternalLsa) {
		this.mapPrefixExternalLsa = mapPrefixExternalLsa;
	}

	/**
	 * @return Returns the mapPrefixExternalLsa.
	 */
	@SuppressWarnings("unchecked")
	public HashMap<Long, AsExternalLSA> getMapPrefixExternalLsa() {
		return (HashMap<Long, AsExternalLSA>) mapPrefixExternalLsa.clone();
	}

	/*
	 * 返回全网路由器id列表
	 */
	public ArrayList<Long> getAllRouterIds() {
		if (this.mapRidRouter.size() == 0) {
			return null;
		}

		Entry<Long, OspfRouter> entry = null;
		Iterator<Entry<Long, OspfRouter>> iterator = this.mapRidRouter
				.entrySet().iterator();
		ArrayList<Long> allRouterIds = new ArrayList<Long>();

		while (iterator.hasNext()) {
			entry = iterator.next();
			allRouterIds.add(entry.getKey());
		}

		return allRouterIds;
	}

	/**
	 * 
	 * @param nexthop
	 * @param interLink
	 */
	public void setInterAsLinks(long nexthop, InterAsLink interLink) {
		if (nexthop != 0 && interLink != null) {
			this.mapNextHopAsLink.put(nexthop, interLink);
		}

	}

}
