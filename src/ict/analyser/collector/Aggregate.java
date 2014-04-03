package ict.analyser.collector;

import ict.analyser.netflow.Netflow;
import ict.analyser.netflow.V5_Packet;
import ict.analyser.netflow.V9_Packet;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

public class Aggregate {
	private ConcurrentHashMap<String, Netflow> allFlows = null;

	public Aggregate() {
		allFlows = new ConcurrentHashMap<String, Netflow>();
	}

	int index = 0;

	public void process(final V5_Packet packet) {
		ArrayList<Netflow> flows = packet.getFlows();
		Netflow flowToAdd = null;
		Netflow flowFound = null;
		String key = null;

		for (int i = 0, len = flows.size(); i < len; i++) {
			flowToAdd = flows.get(i);
			key = flowToAdd.getKey();
			flowFound = this.allFlows.get(key);

			if (flowFound == null) {
				flowToAdd.printDetail();
				this.allFlows.put(key, flowToAdd);
			} else {
				flowFound.addOctets(flowToAdd.getdOctets());
			}
		}
	}

	public void process(final V9_Packet packet) {
		ArrayList<Netflow> flows = packet.getNormalFlows();
		Netflow flowToAdd = null;
		Netflow flowFound = null;

		String key = null;
		for (int i = 0, len = flows.size(); i < len; i++) {
			flowToAdd = flows.get(i);
			key = flowToAdd.getKey();
			flowFound = this.allFlows.get(key);
			flowToAdd.printDetail();

			if (flowFound == null) {
				this.allFlows.put(key, flowToAdd);
			} else {
				flowFound.addOctets(flowToAdd.getdOctets());
			}
		}
	}

	/**
	 * @return Returns the allFlows.
	 */
	public ArrayList<Netflow> getAllFlows() {
		if (this.allFlows.size() == 0) {
			return null;
		}

		ArrayList<Netflow> flows = new ArrayList<Netflow>();

		Entry<String, Netflow> entry = null;
		Iterator<Entry<String, Netflow>> iterator = this.allFlows.entrySet()
				.iterator();
		try {
			while (iterator.hasNext()) {
				entry = iterator.next();

				if (entry.getValue() != null) {
					flows.add((Netflow) entry.getValue().clone());
				}
			}
		} catch (CloneNotSupportedException e) {
			e.printStackTrace();
		}
		return flows;
	}

	public void clearFlows() {
		this.allFlows.clear();
	}
}
