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
public class IsisTopo {

	private String areaId = null;

	private long periodId = 0;

	private int networkType = 0;// 判断是level2——2 还是level1——1

	private ArrayList<Long> asbrIdList = null;// 保存全部的l1/l2路由器id

	private HashMap<Long, Long> mapBrIpId = null;// ASBR的接口ip(long)——设备id

	private HashMap<Long, String> mapLongStrId = null;// long型id——string型id映射
														// 调试使用

	private HashMap<Long, Long> mapIpRouterId = null;// 全部路由器ip地址和router id映射

	private HashMap<Long, IsisRouter> mapIdRouter = null;// router id ——router映射

	private HashMap<Long, Long> mapPrefixRouterId = null;// 拓扑中前缀与路由器id对应的映射,用于根据prefix查找路由器id

	private HashMap<Long, ArrayList<Reachability>> mapPrefixReach = null;

	private HashMap<Integer, TrafficLink> mapLidTlink = null;// link id ——
																// TrafficLink

	public IsisTopo() {
		this.mapBrIpId = new HashMap<Long, Long>();
		this.mapIpRouterId = new HashMap<Long, Long>();
		this.mapLongStrId = new HashMap<Long, String>();
		this.mapIdRouter = new HashMap<Long, IsisRouter>();
		this.mapPrefixRouterId = new HashMap<Long, Long>();
		this.mapLidTlink = new HashMap<Integer, TrafficLink>();
		this.mapPrefixReach = new HashMap<Long, ArrayList<Reachability>>();
	}

	/**
	 * 这里只保存stub网络的prefix ——id 映射（待使用）
	 * 
	 * @param mapPrefixRouterId
	 *            The mapPrefixRouterId to set.
	 */
	public void setMapPrefixRouterId(long prefix, long rid) {
		// 以下注释待叶子节点可以配了再启用

		// Object obj = this.mapPrefixRouterId.get(prefix);
		// long routerId = (obj == null) ? 0 : (Long) obj;

		// if (routerId != 0 && routerId != rid) {//
		// 这个prefix不只一个路由器宣告过，这样的不存,这样保存了stub的
		// this.mapPrefixRouterId.remove(prefix);
		// } else {
		// this.mapPrefixRouterId.put(prefix, rid);
		// // System.out.println("added prefix:"
		// // + IPTranslator.calLongToIp(prefix) + "  router id:"
		// // + IPTranslator.calLongToIp(rid));
		// }
		this.mapPrefixRouterId.put(prefix, rid);
	}

	public void setMapIpRouter(long ip, long routerId) {
		this.mapIpRouterId.put(ip, routerId);
	}

	/**
	 * @param mapPrefixReach
	 *            The mapPrefixReach to set.
	 */
	public void setMapPrefixReach(long prefix, Reachability reach) {

		ArrayList<Reachability> reachList = this.mapPrefixReach.get(prefix);
		if (reachList != null) {
			// System.out.println("put reach:prefix:"
			// + IPTranslator.calLongToIp(prefix)
			// + IPTranslator.calLongToSysId(reach.getSysId()));
			reachList.add(reach);
		} else {
			reachList = new ArrayList<Reachability>();
			reachList.add(reach);
			// System.out.println("aaa put reach:prefix:"
			// + IPTranslator.calLongToIp(prefix) + " reach:"
			// + IPTranslator.calLongToSysId(reach.getSysId()));
			this.mapPrefixReach.put(prefix, reachList);
		}

	}

	public ArrayList<Object[]> getBrByPrefix(long ip, byte mask) {
		Object[] br = null;
		long dMask = IPTranslator.calByteToLong(mask);
		long prefix = ip & dMask;
		// System.out.println("prefix!!!" + IPTranslator.calLongToIp(prefix));
		ArrayList<Object[]> brList = new ArrayList<Object[]>();
		ArrayList<Reachability> reachList = this.mapPrefixReach.get(prefix);
		if (reachList != null) {
			int size = reachList.size();
			Reachability reach = null;
			for (int i = 0; i < size; i++) {
				reach = reachList.get(i);
				br = new Object[2];
				br[0] = reach.getSysId();
				br[1] = reach.getMetric();
				brList.add(br);
			}
		} else {
			int changeCount = 1;
			while (changeCount < 24) { // 循环移位截止：255.0.0.0
				changeCount++;
				// prefix = IPTranslator.getChangedPrefix(ip, dMask);//
				// 计算新的prefix
				prefix <<= 1;
				reachList = this.mapPrefixReach.get(prefix);// 在映射中查找对应reachability
															// list
				if (reachList != null) {// 如果找到了external lsa列表
					int size = reachList.size();
					Reachability reach = null;
					for (int i = 0; i < size; i++) {
						reach = reachList.get(i);
						br = new Object[2];
						br[0] = reach.getSysId();
						br[1] = reach.getMetric();
						brList.add(br);
					}
					break;
				}
			}
		}
		return brList;
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

	/**
	 * 根据ip，mask查找对应路由器id
	 * 
	 * @param ip
	 * @param mask
	 * @return 路由器id
	 */
	public long[] getRidByPrefix(long ip, byte mask) {

		long dmask = IPTranslator.calByteToLong(mask);
		long prefix = ip & dmask;
		long[] result = new long[2];

		Object obj = this.mapPrefixRouterId.get(prefix);// 在前缀——路由器id映射中查找路由器id

		if (obj != null) {
			result[0] = (Long) obj;
			result[1] = prefix;
			return result;
		}

		// 如果没找到这个prefix，循环移位重新计算prefix再查找
		int changeCount = 1;
		// Set<Long> set = this.mapPrefixRouterId.keySet();
		// Iterator<Long> it = set.iterator();
		// while(it.hasNext())
		// {
		// long key = it.next();
		// long rid = this.mapPrefixRouterId.get(key);
		// System.out.println(IPTranslator.calLongToIp(key)
		// +"  id: "+this.mapLongStrId.get(rid));
		// }
		//
		while (changeCount < 24) {
			changeCount++;
			dmask <<= 1;
			prefix = ip & dmask;// 根据ip和新的mask再计算prefix

			// prefix = (prefix << 1)&0x00000000ffffffff;
			obj = this.mapPrefixRouterId.get(prefix);// 再查找

			// System.out.println("changed prefix:"+
			// IPTranslator.calLongToIp(prefix)+"   id:"+ obj);
			if (obj != null) {// 如果找到了，返回
				result[0] = (Long) obj;
				result[1] = prefix;
				return result;
			}
		}
		return null;
	}

	public long getBrIdByIp(long ip) {

		Object obj = this.mapBrIpId.get(ip);

		if (obj == null) {
			// obj = this.mapPrefixRouterId.get(ip);
			// if (obj == null) {
			return 0;
			// }
			// return (Long) obj;
		} else {
			return (Long) obj;
		}
	}

	/**
	 * @return Returns the mapIdRouter.
	 */
	public HashMap<Long, IsisRouter> getMapIdRouter() {
		return mapIdRouter;
	}

	/**
	 * @return Returns the mapPrefixRouterId.
	 */
	public HashMap<Long, Long> getMapPrefixRouterId() {
		return mapPrefixRouterId;
	}

	/**
	 * @return Returns the mapPrefixReach.
	 */
	public HashMap<Long, ArrayList<Reachability>> getMapPrefixReach() {
		return mapPrefixReach;
	}

	/**
	 * @param mapIdRouter
	 *            The mapIdRouter to set.
	 */
	public void setMapIdRouter(long rid, IsisRouter router) {
		this.mapIdRouter.put(rid, router);
	}

	public void setMapBrIpId(long ip, long id) {
		this.mapBrIpId.put(ip, id);
	}

	// /**
	// * @return Returns the mapASBRipId.
	// */
	// public HashMap<Long, Long> getMapASBRipId() {
	// return mapBrIpId;
	// }

	public void setMapLidTraffic(int id) {
		if (id == 0) {
			return;
		}

		TrafficLink link = new TrafficLink();
		this.mapLidTlink.put(id, link);
	}

	/**
	 * @return Returns the mapLidTlink.
	 */
	public HashMap<Integer, TrafficLink> getMapLidTlink() {
		return mapLidTlink;
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
	 * @return Returns the pid.
	 */
	public long getPeriodId() {
		return periodId;
	}

	/**
	 * @param pid
	 *            The pid to set.
	 */
	public void setPid(long pid) {
		this.periodId = pid;
	}

	// /**
	// *
	// *
	// * @param nexthop
	// * @return
	// */
	// public long getRidByNextHop(long nexthop) {
	// Object obj = this.mapIpRouterId.get(nexthop);
	// if (obj == null) {
	// return 0;
	// }
	// return (Long) obj;
	// }

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
	public ArrayList<Long> getBrIdList() {
		return asbrIdList;
	}

	/**
	 * @param asbrIdList
	 *            The asbrIdList to set.
	 */
	public void setBrIdList(ArrayList<Long> asbrIdList) {
		this.asbrIdList = asbrIdList;
	}

	public HashMap<Long, String> getMapLongStrId() {
		return mapLongStrId;
	}

	public void setMapLongStrId(long longid, String strid) {
		if (longid != 0 && strid != null) {
			this.mapLongStrId.put(longid, strid);
		}
	}

}
