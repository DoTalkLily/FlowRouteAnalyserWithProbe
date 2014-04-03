/*
 * Filename: IsIsNode.java
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

import ict.analyser.ospftopo.Link;

import java.util.ArrayList;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-18
 */
public class IsisRouter {
	private long id = 0;// 路由器id
	private int level = 2;// 默认是level 2
	private ArrayList<Long> ips = null;// 接口ip列表
	private ArrayList<Link> links = null;// 链路列表
	private ArrayList<Long> neighborIds = null;// 邻居id列表，与link 一 一对应

	public IsisRouter() {
		ips = new ArrayList<Long>();
		links = new ArrayList<Link>();
		neighborIds = new ArrayList<Long>();
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
	 * @return Returns the level.
	 */
	public int getLevel() {
		return level;
	}

	/**
	 * @param level
	 *            The level to set.
	 */
	public void setLevel(int level) {
		this.level = level;
	}

	/**
	 * @return Returns the id.
	 */
	public long getId() {
		return id;
	}

	/**
	 * @param id
	 *            The id to set.
	 */
	public void setId(long id) {
		this.id = id;
	}

	/**
	 * @return Returns the ips.
	 */
	public ArrayList<Long> getIps() {
		return ips;
	}

	/**
	 * @param ip
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

}
