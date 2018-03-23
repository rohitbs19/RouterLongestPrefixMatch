package edu.wisc.cs.sdn.vnet.rt;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.*;
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
	private ExecutorService executor;
	private ReentrantLock lock;
	private ExecutorService executor_insert;
	private ReentrantLock lock_insert;

	/**
	 * ARP cache for the router
	 */
	private ArpCache arpCache;
	private Timer timer;
	private Timer timer2;
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
	 * @param //routeTableFile the name of the file containing the routing table
	 */


	public void loadRouteTable(String routeTableFile) {

		//in our program this will initialize the route table by adding entries to
		// the subnets directly connected to the router.
		if (routeTableFile != null) {
			System.out.println("fileName val *************** " + routeTableFile);
			if (!routeTable.load(routeTableFile, this)) {
				System.err.println("Error setting up routing table from file "
						+ routeTableFile);
				System.exit(1);
			}
		}
		//after the initialization we need to send a RIP request out of all the router's interfaces
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	/*
	* timer schedules the poll function call as mentioned in the init function */
	class update extends TimerTask {
		public void run() {
			System.out.println("-------------------------------------------------");
			System.out.println("*** POLL INITIATED SEND RIP REQUESTS ***");
			poll();
			System.out.println("-------------------------------------------------");
		}
	}
	public void remove_handler() {
//		if (this.executor != null && this.lock!=null) {
//			lock.lock();
//			try{
				for (RouteEntry name : this.routeTable.getEntries()) {

					if (name.getTtl()!=0 && name.getGatewayAddress()!=0 &&(System.currentTimeMillis() - name.getTtl()) > 30000) {
						this.routeTable.remove(name.getDestinationAddress(), name.getMaskAddress());

					}
				}
				System.out.println(this.routeTable.toString());
//			}finally {
//				lock.unlock();
//			}
//		}
	}
	class update1 extends TimerTask {
		public void run() {
			System.out.println("-------------------------------------------------");
			System.out.println("*** REMOVAL INITIATED REMOVAL RIP REQUESTS ***");
			remove_handler();
			System.out.println("-------------------------------------------------");
		}
	}
//9963
	public void poll() {

		for (String name : this.interfaces.keySet()) {
			sendRequestResponseRIP(this.interfaces.get(name), true, false);
		}
	}
	public void removalHandler_locks() {
		executor = Executors.newFixedThreadPool(3);
		lock = new ReentrantLock();
	}
	public void insert_locks() {
		executor_insert = Executors.newFixedThreadPool(3);
		lock_insert = new ReentrantLock();
	}


//8118

	public void InitRouteTable() {


		/* FIRST INSERT ALL THE IMMEDIATE NEIGHBORS*/
		for (Iface ifaces : this.interfaces.values())
		{
			//int dstIp, int gwIp, int maskIp, Iface ifac
			int mask = ifaces.getSubnetMask();
			int destination = ifaces.getIpAddress() & mask;

			this.routeTable.insert(destination, 0, mask, ifaces, 1);
		}
		System.out.println("*** ROUTE TABLE INITIALIZED AFTER: IMMEDIATE INTERFACES ARE ADDED ***");
		System.out.println("################## AFTER Route Table UPDATE####################");
		System.out.println(this.routeTable.toString());
		System.out.println("################## INITIAL Route Table UPDATE####################");


		System.out.println("*** SENT RIP PACKETS TO ALL INTERFACES IN INIT ***");
		// Send initial RIP update request
		for (Iface ifaces : this.interfaces.values())
		{
			this.sendRequestResponseRIP(ifaces, true, true);
		}

		removalHandler_locks();
		insert_locks();
		this.timer = new Timer();
		this.timer2 = new Timer();
		this.timer2.scheduleAtFixedRate(new update1(), 1000, 1000);
		this.timer.scheduleAtFixedRate(new update(), 10000, 10000);

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
		/*for (Iface iface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
				return false;
			}
		}*/
		/*if (ipPacket.getProtocol() != IPv4.PROTOCOL_UDP) {
			return false;
		}*/
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
	/*sending rip request/response*/
	//clear
	public void sendRequestResponseRIP(Iface inIface, boolean broadcast, boolean isRequest) {


		System.out.println("-------------------------------------------------");
		System.out.println("*** SEND RIP PACKET INITIATED ***");
		System.out.println("-------------------------------------------------");
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udpPacket = new UDP();
		RIPv2 ripPacket = new RIPv2();
		ether.setPayload(ip);
		ip.setPayload(udpPacket);
		udpPacket.setPayload(ripPacket);

		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress("FF:FF:FF:FF:FF:FF");
		if(broadcast)
			ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
		else
			ether.setDestinationMACAddress(inIface.getMacAddress().toBytes());

		ip.setTtl((byte)64);
		ip.setVersion((byte)4);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		if(broadcast)
			ip.setDestinationAddress("224.0.0.9");
		else
			ip.setDestinationAddress(inIface.getIpAddress());

		udpPacket.setSourcePort(UDP.RIP_PORT);
		udpPacket.setDestinationPort(UDP.RIP_PORT);

		ripPacket.setCommand(isRequest ? RIPv2.COMMAND_REQUEST : RIPv2.COMMAND_RESPONSE);
		// enter the rip values into the packet
		for (RouteEntry entry : this.routeTable.getEntries())
		{
			int address = entry.getDestinationAddress();
			int mask = entry.getMaskAddress();
			int next = inIface.getIpAddress();
			int cost = entry.getMetric();

			RIPv2Entry ripEntry = new RIPv2Entry(address, mask, cost);
			ripEntry.setNextHopAddress(next);
			ripPacket.addEntry(ripEntry);
		}

		ether.serialize();
		System.out.println("-------------------------------------------------");
		System.out.println(" %%%%%%%% RIP " + ripPacket.getCommand() + " SENT %%%%%%%%%%%%");
		System.out.println("-------------------------------------------------");
		System.out.println("-------------------------------------------------");
		System.out.println("*** "+ ripPacket.getCommand() +"PACKET SENT " + " THROUGH " + inIface.getName() + " ***");
		System.out.println("-------------------------------------------------");
		this.sendPacket(ether, inIface);
	}
	//basic sanitary checks for IP packet and handles the cases for packet drop

	//399
	public boolean check_removal(int currCost, int newCost) {
		if (currCost != newCost) {
			return false;
		}
		return true;
	}
	public void handleRipRequestResponse(Ethernet etherPacket, Iface inIface) {

		IPv4 ip = (IPv4)etherPacket.getPayload();
		UDP UdpData = (UDP)ip.getPayload();
		RIPv2 rip = (RIPv2)UdpData.getPayload();
		if (rip.getCommand() == RIPv2.COMMAND_REQUEST)
		{

			if (etherPacket.getDestinationMAC().toLong() == MACAddress.valueOf("FF:FF:FF:FF:FF:FF").toLong() && ip.getDestinationAddress() == IPv4.toIPv4Address("224.0.0.9")) {
				System.out.println("*** GOT A BROADCAST REQUEST ****");
				this.sendRequestResponseRIP(inIface, true, false);
				return;
			}
		}
		/*System.out.println("##################BEFORE UPDATE Route Table####################");
		System.out.println(this.routeTable.toString());
		System.out.println("##################BEFORE UPDATE Route Table####################");*/
//		if(ip.getDestinationAddress() == IPv4.toIPv4Address("224.0.0.9")) {
			for (RIPv2Entry ripEntry : rip.getEntries()) {
				int address = ripEntry.getAddress();
				int mask = ripEntry.getSubnetMask();
				int cost = ripEntry.getMetric() + 1;
				int next = ripEntry.getNextHopAddress();


				RouteEntry entry = this.routeTable.lookup(address);
				boolean remove = false;
				if (entry != null && entry.getGatewayAddress()!=0) {
					remove = check_removal(entry.getMetric(), cost);
				}
				/*if (entry != null) {
					System.out.println("--------------------------------------------------------");
					System.out.println("RIP entry in message metric: " + cost);
					System.out.println("entry in routers Routing Table: " + entry.getMetric());

					System.out.println("--------------------------------------------------------");
				}*/

				if (null == entry) {
					this.routeTable.insert(address, next, mask, inIface, cost);

						this.sendRequestResponseRIP(inIface, false, false);
					System.out.println("################## NULL AFTER UPDATE Route Table####################");
					System.out.println(rip.getCommand());
					System.out.println(this.routeTable.toString());
					System.out.println("################## NULL AFTER UPDATE Route Table####################");
					/*

					MAY CAUSE AN ERROR

				*/

				} else if (entry.getMetric() > cost) {
					System.out.println("################## COST AFTER UPDATE Route Table####################");
					System.out.println(cost +" " + entry.getMetric());
					if(!this.routeTable.update(address, mask, next, inIface, cost)){
						System.out.println("SENDING FUCKING NULL FOR SOME REASON @#$%^&*%^$&(*&)&^&%%^$%$(^^&*_^_)&^)^%^&(%()^)&^)*^");
					}
					RouteEntry entry1 = this.routeTable.lookup(address);
					System.out.println("after update cost " + entry1.getMetric() + "and cost is " + cost);

						this.sendRequestResponseRIP(inIface, false, false);
					System.out.println("################## COST AFTER UPDATE Route Table####################");
					System.out.println(this.routeTable.toString());
					System.out.println("##################COST AFTER UPDATE Route Table####################");

				} else if (remove) {
					entry.setTtl(System.currentTimeMillis());
				}

			}
	/*	System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));*/


//		}
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
		//System.out.println("*******************************HANDLE PACK ENTRY NOT HANDLE IP**********************************");
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

	/*trial senderror function*//*



	/*
	 * sanitary checks for the incoming IP packet
	 * */
	private void handleIpPacket(Ethernet etherPacket, Iface inIface) {

		// Make sure it's an IP packet
		// Do route lookup and forward
		boolean normalPacketOrRIP = true;
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		System.out.println("-------------------------------------------------");
		System.out.println("*** HANDLE PACKET UNDER CONTROL" + "IP PACKET ADDR: "
				+ ipPacket.getDestinationAddress() + " ***");

		if (sanitaryChecksIP(etherPacket, inIface)) {
			System.out.println("*** 1: BASIC SANITARY IP CHECKS DONE - IFACE AND - UDP CHECKS ***");


			for (String name : this.interfaces.keySet()) {

				if (ipPacket.getDestinationAddress() == this.interfaces.get(name).getIpAddress()) {
					normalPacketOrRIP = false;
				}
				short protocol = ipPacket.getProtocol();
				System.out.println("*** ipPacket protocol: " + protocol + " ***");
					if (protocol == IPv4.PROTOCOL_UDP) {

						System.out.println("*** 2: ---> protocol equal to UDP ***");

						IPv4 temp = new IPv4();
						temp.setDestinationAddress("224.0.0.9");
						if (ipPacket.getDestinationAddress() == this.interfaces.get(name).getIpAddress()) {
							System.out.println("-------------------------------------------------");
							System.out.println("*** DESTINATION ADDR IS EQUAL TO INTERFACE ADDR ***");


							System.out.println("-------------------------------------------------");
						}
						if (sanitaryChecksUDP(ipPacket)
								|| (ipPacket.getDestinationAddress()==this.interfaces.get(name).getIpAddress())) {
							normalPacketOrRIP = false;
							System.out.println("3: ---> sending the packet to handleRIPPacket");
							handleRipRequestResponse(etherPacket, inIface);
							System.out.println("*******************************END**********************************");
						}
					}
			}
			System.out.println("-------------------------------------------------");
			System.out.println("FATAL ERROR CHECK: IP VALUE: " + ipPacket.getDestinationAddress() + " normalPacketOrRIP: " + normalPacketOrRIP);
			System.out.println("-------------------------------------------------");
			if (normalPacketOrRIP) {
				System.out.println("-------------------------------------------------");
				System.out.println(" *** FORWARD PACKET IP value " + ipPacket.getDestinationAddress() + " ***");
				System.out.println("-------------------------------------------------");
				this.forwardIpPacket(etherPacket, inIface);
			}
		} else {
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
		/*if (bestMatch.getGatewayAddress() != 0) {
			bestMatch.setTtl(System.currentTimeMillis());
		}*/
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


