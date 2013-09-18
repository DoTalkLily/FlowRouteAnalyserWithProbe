/*
 * Filename: OspfRouter.java
 * Copyright: ICT (c) 2012-10-18
 * Description: ospf网络上的路由器节点
 * Author: 25hours
 */
package ict.analyser.ospftopo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-18
 */
public class OspfRouter {
	private long routerId = 0;// 路由器id
	private ArrayList<Long> ips = null;// 接口ip列表
	private ArrayList<Link> links = null;// 链路列表
	private ArrayList<String> areas = null;// 路由器所在区域列表
	private HashMap<Long, Long> mapIpPrefix = null;// 路由器ip和前缀映射
	private ArrayList<Long> neighborIds = null;// 邻居id列表，与link 一 一对应
	private HashMap<Integer, Integer> mapInputLinkid = null;// 接口索引号与链路id对应关系

	public OspfRouter() {
		ips = new ArrayList<Long>();
		links = new ArrayList<Link>();
		areas = new ArrayList<String>();
		neighborIds = new ArrayList<Long>();
		mapIpPrefix = new HashMap<Long, Long>();
		mapInputLinkid = new HashMap<Integer, Integer>();
	}

	/**
	 * @return Returns the routerId.
	 */
	public long getRouterId() {
		return routerId;
	}

	/**
	 * @param routerId
	 *            The routerId to set.
	 */
	public void setRouterId(long routerId) {
		this.routerId = routerId;
	}

	/**
	 * @return Returns the ips.
	 */
	public ArrayList<Long> getIps() {
		return ips;
	}

	/**
	 * @return Returns the links.
	 */
	public ArrayList<Link> getLinks() {
		return links;
	}

	/**
	 * @return Returns the neighborIds.
	 */
	public ArrayList<Long> getNeighborIds() {
		return neighborIds;
	}

	/**
	 * @param ips
	 *            The ips to set.
	 */
	public void setIp(long ip) {
		if (ip != 0) {
			this.ips.add(ip);
		}
	}

	/**
	 * @param link
	 *            The links to set.
	 */
	public void setLink(Link link) {
		if (link != null) {
			this.links.add(link);
			this.mapIpPrefix.put(link.getMyInterIp(), link.getPrefix());
		}
	}

	/**
	 * @param neighborId
	 *            The neighborIds to set.
	 */
	public void setNeighborId(long neighborId) {
		if (neighborId != 0) {
			this.neighborIds.add(neighborId);
		}
	}

	/**
	 * @return Returns the areas.
	 */
	public ArrayList<String> getAreas() {
		return areas;
	}

	/**
	 * @param areas
	 *            The areas to set.
	 */
	public void addArea(String area) {

		if (area != null && !this.areas.contains(area)) {
			this.areas.add(area);
			// System.out.println("router id:"
			// + IPTranslator.calLongToIp(this.routerId) + " area:" + area
			// + " added!");
		}
	}

	public void setInputLinkid(int input, int linkid) {
		if (input >= 0 && linkid >= 0) {
			this.mapInputLinkid.put(input, linkid);
		}
	}

	public int getLinkidByInput(int input) {
		Object obj = mapInputLinkid.get(input);
		return obj == null ? 0 : (Integer) obj;
	}

	public long getPrefixByLinkId(int linkid) {
		int size = this.links.size();
		Link link = null;

		for (int i = 0; i < size; i++) {
			link = this.links.get(i);

			if (linkid == link.getLinkId()) {
				return link.getPrefix();
			}
		}
		return 0;
	}

	public long getIpByPrefix(long prefix) {
		Map.Entry<Long, Long> entry;
		Iterator<Entry<Long, Long>> iter = this.mapIpPrefix.entrySet()
				.iterator();

		while (iter.hasNext()) {
			entry = iter.next();
			if (entry.getValue() == prefix) {
				return entry.getKey();
			}
		}

		return 0;
	}

	public long getPrefixByIp(long ip) {

		if (ip == 0) {
			return 0;
		}

		return this.mapIpPrefix.get(ip);
	}
}
