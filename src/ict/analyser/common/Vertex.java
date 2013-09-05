/*
 * Filename: Vertex.java
 * Copyright: ICT (c) 2012-11-3
 * Description: 
 * Author: 25hours
 */
package ict.analyser.common;

import ict.analyser.flow.Path;
import ict.analyser.ospftopo.Link;

import java.util.ArrayList;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-11-3
 */
public class Vertex {

	private Path path = null;// 到原点路径

	private long routerId = 0;// 路由器id

	private ArrayList<Link> neighbor = null;// 连接邻居链路

	public Vertex() {
		path = new Path();
		neighbor = new ArrayList<Link>();
	}

	public Vertex(int cost) {
		path = new Path();
		path.setTotalCost(cost);
		neighbor = new ArrayList<Link>();
	}

	/**
	 * @return Returns the path.
	 */
	public Path getPath() {
		return path;
	}

	/**
	 * @param path
	 *            The path to set.
	 */
	public void setPath(ArrayList<Link> links) {
		this.path.setLinks(links);
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
	 * @return Returns the neighbor.
	 */
	public ArrayList<Link> getNeighbor() {
		return neighbor;
	}

	/**
	 * @param neighbor
	 *            The neighbor to set.
	 */
	public void setNeighbor(ArrayList<Link> neighbor) {
		this.neighbor = neighbor;
	}

	/**
	 * @return Returns the totalcost.
	 */
	public int getTotalcost() {
		return this.path.getTotalCost();
	}

	/**
	 * @param totalcost
	 *            The totalcost to set.
	 */
	public void setTotalcost(int totalcost) {
		this.path.setTotalCost(totalcost);
	}

	/**
	 * 
	 * 
	 * @param neighborLink
	 */
	public void addLink(Link link) {
		// TODO Auto-generated method stub
		this.path.addLinks(link);
	}

}
