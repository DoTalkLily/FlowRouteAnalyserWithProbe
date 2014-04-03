/*
 * Filename: IsisTopo.java
 * Copyright: Huawei Copyright (c) 2012-10-18
 * Description: 
 * Author: 25hours
 *
 * Modified by:
 * Modified time: 2012-10-18
 * Trace ID:
 * CR No:
 * Modified content:
 */
package ict.analyser.isistopo;

import ict.analyser.common.Constant;
import ict.analyser.tools.IPTranslator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map.Entry;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-18
 */
public class IsisTopo {
	private long periodId = 0;// 周期id
	private int networkType = 0;// 判断是level2——2 还是level1——1
	private String areaId = null;// 区域id
	private LinkedList<Long> borderIdList = null;// 保存全部的l1/l2路由器id
	private HashMap<Long, Long> mapBrIpId = null;// ASBR的接口ip(long)——设备id
	private HashMap<Long, String> mapLongStrId = null;// long型id——string型id映射
	private HashMap<Long, IsisRouter> mapIdRouter = null;// router id ——router映射
	private HashMap<Long, Long> mapPrefixRidForStub = null;// 只保存经过‘过滤’过的可能连接终端的‘stub’子网preifx——id映射
	private HashMap<Long, Reachability> mapPrefixRidForL2 = null;// level2内保存边界路由器宣告的前缀信息——路由器id映射
	private HashMap<Long, LinkedList<Reachability>> mapPrefixReachForL1 = null;// level1网络专用前缀——可达性对象映保存l1/l2宣告的reachability信息

	public IsisTopo(boolean initial) {
		if (!initial) {
			return;
		}

		this.mapBrIpId = new HashMap<Long, Long>();
		this.mapLongStrId = new HashMap<Long, String>();
		this.mapIdRouter = new HashMap<Long, IsisRouter>();
		this.mapPrefixRidForStub = new HashMap<Long, Long>();
		this.mapPrefixRidForL2 = new HashMap<Long, Reachability>();
		this.mapPrefixReachForL1 = new HashMap<Long, LinkedList<Reachability>>();
	}

	/**
	 * 这里只保存stub网络的prefix ——id
	 * 
	 * @param mapPrefixRouterId
	 *            The mapPrefixRouterId to set.
	 */
	public void setMapStubPrefixRId(long prefix, long rid) {
		if (prefix <= 0 || rid <= 0) {
			return;
		}

		if (this.mapPrefixRidForStub.containsKey(prefix)) {// 如果有就说明不是stub网段，删除，否则添加
			this.mapPrefixRidForStub.remove(prefix);
		} else {
			this.mapPrefixRidForStub.put(prefix, rid);
		}
	}

	/**
	 * 根据设备id查找设备对象
	 * 
	 * @param routerId
	 *            设备id
	 * @return 设备对象
	 */
	public IsisRouter getRouterById(long routerId) {
		if (routerId == 0) {
			System.out.println("router id is illegal in IsisAnalyser！");
			return null;
		}

		return this.mapIdRouter.get(routerId);

	}

	/*
	 * ‘源’根据router ip在某个stub中
	 */
	public long getSrcRidByPrefix(long ip, byte mask) {
		long dmask = IPTranslator.calByteToLong(mask);
		long prefix = ip & dmask;
		int changeCount = 0;
		Object obj;

		while (changeCount < 24) {
			obj = this.mapPrefixRidForStub.get(prefix);

			if (obj != null) {// 在前缀——路由器id映射中查找路由器id
				return (Long) obj;
			}

			changeCount++;
			dmask <<= 1;
			prefix = ip & dmask;// 根据ip和新的mask再计算prefix
		}

		return 0;
	}

	/**
	 * 根据ip，mask在stub中查找对应路由器id
	 * 
	 * @param ip
	 * @param mask
	 * @return 路由器id
	 */
	public Object[] getRidByPrefix(long ip, byte mask, boolean isLevel2) {
		long dmask = IPTranslator.calByteToLong(mask);
		long prefix = ip & dmask;
		Object[] result = new Object[2];// 当在stub中找到prefix，则只返回一个id，在prefixReach映射中找到，则或者是一个id，或者是id——metric映射，两个里面都没找到，则返回保存所有l1/l2路由器的id列表，在level2网络中只会有前两种情况发生，第一个obj是一个标记，i表示第i中情况
		int changeCount = 0;

		while (changeCount < 24) {
			if (this.mapPrefixRidForStub.containsKey(prefix)) {// 在前缀——路由器id映射中查找路由器id
				result[0] = Constant.IN_STUB;
				result[1] = this.mapPrefixRidForStub.get(prefix);
				return result;
			}

			if (isLevel2) {
				if (this.mapPrefixRidForL2.containsKey(prefix)) {
					result[0] = Constant.FOUND_IN_REACH;
					result[1] = this.mapPrefixRidForL2.get(prefix).getSysId();
					return result;
				}
			} else {
				if (this.mapPrefixReachForL1.containsKey(prefix)) {
					result[0] = Constant.FOUND_IN_REACH;
					result[1] = this.mapPrefixReachForL1.get(prefix);
					return result;
				}
			}

			changeCount++;
			dmask <<= 1;
			prefix = ip & dmask;// 根据ip和新的mask再计算prefix
		}

		if (isLevel2) {
			return null;
		}

		result[0] = Constant.NOT_IN_REACH;
		result[1] = this.getBrIdList();
		return result;
	}

	public long getBrIdByIp(long ip) {
		if (ip <= 0 || !this.mapBrIpId.containsKey(ip)) {
			return 0;
		}

		return this.mapBrIpId.get(ip);
	}

	/**
	 * @return Returns the mapIdRouter.
	 */
	public HashMap<Long, IsisRouter> getMapIdRouter() {
		return mapIdRouter;
	}

	/**
	 * @param mapIdRouter
	 *            The mapIdRouter to set.
	 */
	public void setMapIdRouter(long rid, IsisRouter router) {
		if (rid == 0 || router == null) {
			return;
		}

		this.mapIdRouter.put(rid, router);
	}

	public void setMapBrIpId(long ip, long id) {
		this.mapBrIpId.put(ip, id);
	}

	/**
	 * @return Returns the pid.
	 */
	public long getPeriodId() {
		return periodId;
	}

	/**
	 * @param pid
	 *            The pid to set.
	 */
	public void setPeriodId(long pid) {
		this.periodId = pid;
	}

	/**
	 * @return Returns the networkType.
	 */
	public int getNetworkType() {
		return networkType;
	}

	/**
	 * @param networkType
	 *            The networkType to set.
	 */
	public void setNetworkType(int networkType) {
		this.networkType = networkType;
	}

	/**
	 * @return Returns the asbrIdList.
	 */
	public LinkedList<Long> getBrIdList() {
		return borderIdList;
	}

	/**
	 * @param asbrIdList
	 *            The asbrIdList to set.
	 */
	public void addToBrIdList(long brId) {
		if (brId <= 0) {
			return;
		}

		if (this.borderIdList == null) {
			this.borderIdList = new LinkedList<Long>();
		}
		this.borderIdList.add(brId);
	}

	public HashMap<Long, String> getMapLongStrId() {
		return mapLongStrId;
	}

	public void setMapLongStrId(long longid, String strid) {
		if (longid != 0 && strid != null) {
			this.mapLongStrId.put(longid, strid);
		}
	}

	public ArrayList<Long> getAllRouterIds() {
		if (this.mapIdRouter.size() == 0) {
			return null;
		}

		Entry<Long, IsisRouter> entry = null;
		Iterator<Entry<Long, IsisRouter>> iterator = this.mapIdRouter
				.entrySet().iterator();
		ArrayList<Long> allRouterIds = new ArrayList<Long>();

		while (iterator.hasNext()) {
			entry = iterator.next();
			allRouterIds.add(entry.getKey());
		}

		return allRouterIds;
	}

	/**
	 * @return Returns the areaId.
	 */
	public String getAreaId() {
		return areaId;
	}

	/**
	 * @param areaId
	 *            The areaId to set.
	 */
	public void setAreaId(String areaId) {
		this.areaId = areaId;
	}

	/**
	 * @param mapPrefixRidForL2
	 *            level2网络中，要考虑路由聚合情况，分为： 1. 如果所有边界路由器都配置路由聚合，那么选宣告metric最小的 2.
	 *            如果有配置聚合，有没配置聚合，那么用最长匹配，如果有多个最长匹配，选metric最小的，暂不考虑负载分担
	 */
	public void setMapPrefixReachForL2(long prefix, long sysId, int metric) {
		if (prefix <= 0 || sysId <= 0) {
			return;
		}

		if (this.mapPrefixRidForL2.containsKey(prefix)) {
			Reachability tmp = this.mapPrefixRidForL2.get(prefix);

			if (tmp.getMetric() > metric) {
				tmp.setMetric(metric);
				tmp.setSysId(sysId);
			}
		} else {
			Reachability reach = new Reachability();
			reach.setSysId(sysId);
			reach.setMetric(metric);
			reach.setPrefix(prefix);
			this.mapPrefixRidForL2.put(prefix, reach);
		}
	}

	/**
	 * @param mapPrefixReachForL1
	 *            level1
	 *            网络中，由于要考虑重分发，因此这里保存所有边界路由器宣告的prefix——List<Reachability>映射
	 * 
	 */
	public void setMapPrefixReachForL1(long prefix, long sysId, int metric) {
		if (prefix <= 0 || sysId <= 0) {
			return;
		}

		Reachability reach = new Reachability();
		reach.setSysId(sysId);
		reach.setPrefix(prefix);
		reach.setMetric(metric);

		if (this.mapPrefixReachForL1.containsKey(prefix)) {
			this.mapPrefixReachForL1.get(prefix).add(reach);
		} else {
			LinkedList<Reachability> list = new LinkedList<Reachability>();
			list.add(reach);
			this.mapPrefixReachForL1.put(prefix, list);
		}
	}

	/**
	 * @return Returns the mapPrefixRidForStub.
	 */
	@SuppressWarnings("unchecked")
	public HashMap<Long, Long> getMapPrefixRidForStub() {
		return (HashMap<Long, Long>) mapPrefixRidForStub.clone();
	}

	/**
	 * @return Returns the mapPrefixRidForL2.
	 */
	@SuppressWarnings("unchecked")
	public HashMap<Long, Reachability> getMapPrefixRidForL2() {
		return (HashMap<Long, Reachability>) mapPrefixRidForL2.clone();
	}

	/**
	 * @return Returns the mapPrefixReachForL1.
	 */
	@SuppressWarnings("unchecked")
	public HashMap<Long, LinkedList<Reachability>> getMapPrefixReachForL1() {
		return (HashMap<Long, LinkedList<Reachability>>) mapPrefixReachForL1
				.clone();
	}

	/**
	 * @param mapPrefixRidForStub
	 *            The mapPrefixRidForStub to set.
	 */
	public void setMapPrefixRidForStub(HashMap<Long, Long> mapPrefixRidForStub) {
		this.mapPrefixRidForStub = mapPrefixRidForStub;
	}

	/**
	 * @param mapPrefixRidForL2
	 *            The mapPrefixRidForL2 to set.
	 */
	public void setMapPrefixRidForL2(
			HashMap<Long, Reachability> mapPrefixRidForL2) {
		this.mapPrefixRidForL2 = mapPrefixRidForL2;
	}

	/**
	 * @param mapPrefixReachForL1
	 *            The mapPrefixReachForL1 to set.
	 */
	public void setMapPrefixReachForL1(
			HashMap<Long, LinkedList<Reachability>> mapPrefixReachForL1) {
		this.mapPrefixReachForL1 = mapPrefixReachForL1;
	}

}
