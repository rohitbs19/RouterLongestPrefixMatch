package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import java.util.Timer;
import java.util.TimerTask;

import net.floodlightcontroller.packet.*;
/*
 * COMMENTS FOR p3
 * 1: the load function in the route table class would be responsible for initializing a route table
 * 1-2: and add the initial entries for the subnets that are directly reachable via the router's interfaces.
 * 2: the update and insert methods in the route table class would be instrumental in
 * 2-2: manipulating/maintaining the route table.
 * 3:
 * */

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */

public class Router extends Device {
	/**
	 * Routing table for the router
	 */
	private RouteTable routeTable;

	/**
	 * ARP cache for the router
	 */
	private ArpCache arpCache;
	private Timer timer;
	/**
	 * Creates a router for a specific host.
	 *
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	/**
	 * Load a new routing table from a file.
	 *
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {

		//in our program this will initialize the route table by adding entries to
		// the subnets directly connected to the router.
		if (routeTableFile != null) {


			if (!routeTable.load(routeTableFile, this)) {
				System.err.println("Error setting up routing table from file "
						+ routeTableFile);
				System.exit(1);
			}
		} else {
			InitRouteTable();
		}
		//after the initialization we need to send a RIP request out of all the router's interfaces
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	class update extends TimerTask {
		public void run() {
			poll();
		}
	}

	public void poll() {
		for (String name : this.interfaces.keySet()) {
			sendRequestResponseRIP(this.interfaces.get(name), true, false);
		}
	}
	public void InitRouteTable() {
		//make a route table with entries to associated interfaces
		for (String name : this.interfaces.keySet()) {
			int mask = this.interfaces.get(name).getSubnetMask();
			routeTable.insert(this.interfaces.get(name).getIpAddress() & this.interfaces.get(name).getSubnetMask(), 0, mask, this.interfaces.get(name), 1);
		}
		System.out.println(this.routeTable.toString());
		this.timer = new Timer();
		timer.scheduleAtFixedRate(new update(), 1000, 1000);
	}

	/*sending rip request/response*/
	public void sendRequestResponseRIP(Iface inIface, boolean multiOrBroad, boolean requestUnresp) {

		//make a new ether packet
		Ethernet etherPacket = new Ethernet();
		IPv4 ipPacket = new IPv4();
		UDP udpPacket = new UDP();
		RIPv2 ripPacket = new RIPv2();
		etherPacket.setPayload(ipPacket);
		ipPacket.setPayload(udpPacket);
		udpPacket.setPayload(ripPacket);
		//encapsulation done
		//enter UDP and rip credentials into the packets
		udpPacket.setSourcePort(UDP.RIP_PORT);
		udpPacket.setDestinationPort(UDP.RIP_PORT);
		ipPacket.setProtocol(IPv4.PROTOCOL_UDP);
		ipPacket.setVersion((byte) 4);
		ipPacket.setTtl((byte) 15);
		if (multiOrBroad) {
			etherPacket.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
			ipPacket.setDestinationAddress("244.0.0.9");
		} else {
			etherPacket.setDestinationMACAddress(inIface.getMacAddress().toString());
			ipPacket.setDestinationAddress(inIface.getIpAddress());
		}

		if (requestUnresp) {
			ripPacket.setCommand(RIPv2.COMMAND_REQUEST);
		} else {
			ripPacket.setCommand(RIPv2.COMMAND_RESPONSE);
		}
		for (RouteEntry name : routeTable.getEntries()) {
			int ip = name.getDestinationAddress();
			int mask = name.getMaskAddress();
			Iface nextHop = name.getInterface();
			int metric = name.getMetric();
			RIPv2Entry newEntry = new RIPv2Entry(ip, mask, metric);
			newEntry.setNextHopAddress(nextHop.getIpAddress());
			ripPacket.addEntry(newEntry);
		}
		etherPacket.serialize();
		sendPacket(etherPacket, inIface);

	}

	public boolean sanitaryChecksIP(Ethernet etherPacket, Iface inIface) {
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return false;
		}

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		System.out.println("Handle IP packet");

		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum) {
			return false;
		}

		// Check TTL
		ipPacket.setTtl((byte) (ipPacket.getTtl() - 1));
		if (0 == ipPacket.getTtl()) {
			return false;
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
				return false;
			}
		}
		if (ipPacket.getProtocol() != IPv4.PROTOCOL_UDP) {
			return false;
		}
		return true;
	}

	public boolean sanitaryChecksUDP(IPv4 ipPacket) {
		UDP udpPacket = (UDP) ipPacket.getPayload();
		short origCKsum = udpPacket.getChecksum();
		udpPacket.resetChecksum();
		byte[] serialized = udpPacket.serialize();
		udpPacket.deserialize(serialized, 0, serialized.length);
		short calcCKsum = udpPacket.getChecksum();
		if (calcCKsum != origCKsum) {
			return false;
		}
		if (udpPacket.getDestinationPort() != UDP.RIP_PORT) {
			return false;
		}
		if (udpPacket.getSourcePort() != UDP.RIP_PORT) {
			return false;
		}
		return true;
	}

	public void handleRipRequestResponse(Ethernet etherPacket, Iface inIface) {
		/*fist do all the necessary sanity checks from p2 and then decide whether to take in entries from this or not
		 * if the rip command is of type request send response accordingly
		 * */
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		UDP udpPacket = (UDP) ipPacket.getPayload();
		RIPv2 ripPacket = (RIPv2) udpPacket.getPayload();
		IPv4 temp = new IPv4();
		temp.setDestinationAddress("224.0.0.9");
		if (sanitaryChecksIP(etherPacket, inIface) && sanitaryChecksUDP(ipPacket)) {
			if (ripPacket.getCommand() == RIPv2.COMMAND_REQUEST) {
				if (ipPacket.getDestinationAddress() == temp.getDestinationAddress() && etherPacket.getDestinationMAC() == MACAddress.valueOf("FF:FF:FF:FF:FF:FF")) {
					sendRequestResponseRIP(inIface, true, false);
				}
			}
		}
		temp = null;

		//check all the entries and decide whether to keep entries or update them accordingly

		for (RIPv2Entry name : ripPacket.getEntries()) {
			int ip = name.getAddress();
			int mask = name.getSubnetMask();
			int nextHop = name.getNextHopAddress();
			boolean srcLookup = false;
			RouteEntry src = null;
			int metric = 0;
			if (ipPacket.getSourceAddress() != 0) {
				src = routeTable.lookup(ipPacket.getSourceAddress());
			}
			//Added some extra complexity see how it works!!!!
			if (src != null) {
				 metric = name.getMetric() + src.getMetric();
			} else {
				metric = name.getMetric() + 1;
			}
			int gatewayIP = name.getNextHopAddress();
			RouteEntry holds = routeTable.lookup(ip);
			// doesn't really handle removal of that entry or in other words replace
			if (holds == null){
				routeTable.insert(ip, gatewayIP, mask, inIface, metric);
				for (String temp_name : this.interfaces.keySet()) {
					sendRequestResponseRIP(inIface, false, false);
				}
			} else if (holds.getMetric() < metric) {
				routeTable.update(ip, mask, gatewayIP, inIface, metric);
				for (String temp_name : this.interfaces.keySet()) {
					sendRequestResponseRIP(inIface, false, false);
				}
			}
		}
	}





	/*
	 * add a method for maintaining the route table
	 * that is
	 *
	 * 1: sending an unsolicited RIP response every 10 seconds and
	 * 2: this will be done through handle packet
	 * 3: maintaining the route table by deleting entries whose TTL has exceeded past 30 sec mark
	 * 3-2: never remove route entries for the subnets that are directly reachable via the router's
	 * 3-2: interfaces
	 *
	 * */
	public void pollRouteTable() {
		long currTime = System.currentTimeMillis();
		while (true) {

		}
	}
	/*
	 * make a new method which makes the required RIP packet and encapsultes it into UDP and etherpacket
	 * accordingly ----- This is a convenience function to reduce clutter in handle packet and increase reuse.'
	 *T
	 * */

	/**
	 * Load a new ARP cache from a file.
	 *
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile) {
		if (!arpCache.load(arpCacheFile)) {
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 *
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface     the interface on which the packet was received
	 */
	/*
	 * change handle packets to check if the packet received is destined to a 244.0.0.9 addr and
	 * and is using UDP protocol and respective ports.
	 * 1: edit the routing table by inserting/updating on the basis of the incoming RIP packet from UDP protocol
	 * 2: then decide to send a RIP resp. on the basis if the incoming packet is a request or not
	 *
	 * more on 1:
	 * 1: if the message contains information about an existing route table entry
	 * 1-2: then compare the route table entry's metric with the metric mentioned in the message
	 * 2: if the route table doesn't contain information about what the message talks about
	 * 2-2: then insert the entry into the route table. */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets                                             */

		switch (etherPacket.getEtherType()) {
			case Ethernet.TYPE_IPv4:
				this.handleIpPacket(etherPacket, inIface);
				break;
			// Ignore all other packet types, for now
		}

		/********************************************************************/
	}

	/*
	 * sanitary checks for the incoming IP packet
	 * */
	private void handleIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		// Do route lookup and forward
		if (sanitaryChecksIP(etherPacket, inIface)) {
			this.forwardIpPacket(etherPacket, inIface);
		}else{
			return;
		}

	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}
		System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch) {
			return;
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface) {
			return;
		}

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop) {
			nextHop = dstAddr;
		}

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry) {
			return;
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}
}
