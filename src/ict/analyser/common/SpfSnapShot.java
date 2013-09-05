/*
 * Filename: SpfSnapShort.java
 * Copyright: ICT (c) 2012-11-16
 * Description: 
 * Author: 25hours
 */
package ict.analyser.common;


import java.util.HashMap;

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-11-16
 */
public class SpfSnapShot {

	HashMap<Long, Vertex> spfTree = null;// 最优路径上的路由器id——路由器对象

	HashMap<Long, Vertex> candidatesMap = null;// candidate集合中路由器id——路由器对象

	/**
	 * @return Returns the spfTree.
	 */
	public HashMap<Long, Vertex> getSpfTree() {
		return spfTree;
	}

	/**
	 * @param spfTree
	 *            The spfTree to set.
	 */
	public void setSpfTree(HashMap<Long, Vertex> spfTree) {
		this.spfTree = spfTree;
	}

	/**
	 * @return Returns the candidatesMap.
	 */
	public HashMap<Long, Vertex> getCandidatesMap() {
		return candidatesMap;
	}

	/**
	 * @param candidatesMap
	 *            The candidatesMap to set.
	 */
	public void setCandidatesMap(HashMap<Long, Vertex> candidatesMap) {
		this.candidatesMap = candidatesMap;
	}

}
