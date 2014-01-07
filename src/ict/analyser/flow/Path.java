/*
 * Filename: Path.java
 * Copyright: ICT (c) 2012-10-30
 * Description: 保存一条flow的路径
 * Author: 25hours
 */
package ict.analyser.flow;

import ict.analyser.ospftopo.Link;
import ict.analyser.tools.IPTranslator;

import java.util.ArrayList;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-30
 */
public class Path {
	private long srcRouterId = 0;// 源路由器
	private long dstRouterId = 0;// 目的路由器
	private int totalCost = Integer.MAX_VALUE;// 整条路径的总cost
	private ArrayList<Link> links = null;// 域内netflow所经过的所哟link,暂未使用，等链路需要精确到接口级别的时候再使用

	public Path() {
		links = new ArrayList<Link>();
	}

	/**
	 * 得到链路上的路由器id列表 用“|”分隔
	 * 
	 * @return 返回路由器id列表字符串
	 */
	public String getPath() {
		long myId = 0;
		long neighborId = 0;
		Link link = null;
		String routerIds = "";

		int size = this.links.size();

		if (size > 0) {
			link = this.links.get(0);
			myId = link.getMyId();
			neighborId = link.getNeighborId();

			if (myId != 0 && neighborId != 0) {
				routerIds += myId + "|";
				routerIds += neighborId;
			}

			for (int i = 1; i < size; i++) {
				link = this.links.get(i);
				neighborId = link.getNeighborId();
				if (neighborId != 0) {
					routerIds += "|" + neighborId;
				}
			}
		} else {// 针对源路由器和目的路由器相同的情况
			routerIds = this.srcRouterId + "";
		}
		return routerIds;
	}

	/**
	 * 得到链路上的路由器id列表 用“|”分隔
	 * 
	 * @return 返回路由器id列表字符串
	 */
	public String getPathInIpFormat() {
		String myId = null;
		String neighborId = null;
		String routerIds = "";
		Link link = null;

		int size = this.links.size();

		if (size > 0) {
			link = this.links.get(0);
			myId = IPTranslator.calLongToIp(link.getMyId());
			neighborId = IPTranslator.calLongToIp(link.getNeighborId());

			if (myId != null && neighborId != null) {
				routerIds += myId + "|";
				routerIds += neighborId;
			}

			for (int i = 1; i < size; i++) {
				link = this.links.get(i);
				neighborId = IPTranslator.calLongToIp(link.getNeighborId());

				if (neighborId != null) {
					routerIds += "|" + neighborId;
				}
			}
		} else {
			routerIds = IPTranslator.calLongToIp(srcRouterId);
		}
		// System.out.println("links size:" + size);
		return routerIds;
	}

	public ArrayList<Long> getPathInIsisIpFormat() {
		ArrayList<Long> ids = new ArrayList<Long>();

		long myId = 0;
		long neighborId = 0;
		Link link = null;

		int size = this.links.size();

		if (size > 0) {
			link = this.links.get(0);
			myId = link.getMyId();
			neighborId = link.getNeighborId();

			if (myId != 0 && neighborId != 0) {
				ids.add(myId);
				ids.add(neighborId);
			}

			for (int i = 1; i < size; i++) {
				link = this.links.get(i);
				neighborId = link.getNeighborId();

				if (neighborId != 0) {
					ids.add(neighborId);
				}
			}
		} else {
			ids.add(srcRouterId);
		}
		// System.out.println("links size:" + size);
		return ids;
	}

	public String getPrefixsOnPath() {
		Link link = null;
		long prefix = 0;

		int size = this.links.size();
		String prefixStrs = "";

		if (size > 0) {
			for (int i = 0; i < size - 1; i++) {
				link = this.links.get(i);
				prefix = link.getMyInterIp() & link.getMask();

				// System.out.println("my ip:" + link.getMyInterIp() + " mask:"
				// + link.getMask());
				if (prefix != 0) {
					prefixStrs += prefix + "|";
				}
			}
			link = this.links.get(size - 1);
			prefix = link.getMyInterIp() & link.getMask();
			prefixStrs += prefix;
		}
		// System.out.println("prefix strs:" + prefixStrs);
		return prefixStrs;
	}

	public long getSourceId() {
		if (this.links.size() > 0) {
			return this.links.get(0).getMyId();
		}
		return 0;
	}

	/**
	 * 
	 * 
	 * @param partBest
	 */
	public void appendPath(Path path) {
		if (path != null) {
			ArrayList<Link> linksToAdd = path.getLinks();
			int size = linksToAdd.size();

			for (int i = 0; i < size; i++) {
				this.links.add(linksToAdd.get(i));
			}

			totalCost += path.getTotalCost();
		}
	}

	public void appendLink(Link link) {
		this.links.add(link);
		totalCost += link.getMetric();
	}

	public void addTotalCost(int cost) {
		this.totalCost += cost;
	}

	/**
	 * @return Returns the links.
	 */
	public ArrayList<Link> getLinks() {
		return links;
	}

	/**
	 * @param links
	 *            The links to set.
	 */
	public void addLinks(Link link) {
		this.links.add(link);
	}

	/**
	 * @return Returns the totalCost.
	 */
	public int getTotalCost() {
		return totalCost;
	}

	/**
	 * @param totalCost
	 *            The totalCost to set.
	 */
	public void setTotalCost(int totalCost) {
		this.totalCost = totalCost;
	}

	/**
	 * @param links
	 *            The links to set.
	 */
	public void setLinks(ArrayList<Link> links) {
		this.links.clear();
		this.links.addAll(links);
	}

	/**
	 * @return Returns the srcRouter.
	 */
	public long getSrcRouter() {
		return srcRouterId;
	}

	/**
	 * @param srcRouter
	 *            The srcRouter to set.
	 */
	public void setSrcRouter(long srcRouter) {
		this.srcRouterId = srcRouter;
	}

	/**
	 * @return Returns the srcRouterId.
	 */
	public long getSrcRouterId() {
		return srcRouterId;
	}

	/**
	 * @param srcRouterId
	 *            The srcRouterId to set.
	 */
	public void setSrcRouterId(long srcRouterId) {
		this.srcRouterId = srcRouterId;
	}

	/**
	 * @return Returns the dstRouterId.
	 */
	public long getDstRouterId() {
		return dstRouterId;
	}

	/**
	 * @param dstRouterId
	 *            The dstRouterId to set.
	 */
	public void setDstRouterId(long dstRouterId) {
		this.dstRouterId = dstRouterId;
	}
}
