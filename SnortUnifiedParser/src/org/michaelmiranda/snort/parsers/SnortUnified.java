/**
 * Copyright (c) 2010, Michael J. A. Miranda
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice, 
 *      this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright notice,
 *      this list of conditions and the following disclaimer in the documentation 
 *      and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Project: SnortUnifiedParser
 * Filename: SnortUnified.java
 * Package: org.michaelmiranda.snort.parsers
 * Timestamp: Mar 5, 2010 10:03:56 PM
 * Author: Michael J. A. Miranda
 */
package org.michaelmiranda.snort.parsers;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;

/**
 * @author Michael J. A. Miranda
 *
 */
public class SnortUnified {

	private FileChannel fc;
	private ByteBuffer buf;
	private byte[] bytes1;
	private byte[] bytes2;
	private byte[] bytes4;
	private byte[] bytes6;
	
	
	private SnortPacketInterface snortPacket;
	private Unified2RecordHeader header;
	private Unified2Packet packet;
	private EthernetFramePacket ethernetPacket;
	private IPPacket ipPacket;
	
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String f = "snort2.log.1267172679";
		SnortUnified su = new SnortUnified();
		su.parse(f);
	}
	
	public SnortUnified() {
		bytes1 = new byte[1];
		bytes2 = new byte[2];
		bytes4 = new byte[4];
		bytes6 = new byte[6];
	}
	
	public void parse(String filename) {
		
		//DataInputStream inputStream = Utilities.getBinaryFileStream(filename);
		fc = Utilities.getBinaryFilechannel(filename);
		this.readRecordHeader();
		switch ((int)header.getType()) {
			// Snort Event Record
			case 7:
				break;
			// IPv4 Packet Record
			case 2:
				this.readPacketHeader(header.getLength());
				// based on the link type assign to proper packet 
				switch ((int) packet.getLinktype()) {
					case ETHERNET_LINK:
						ethernetPacket = this.getEthernetPacketClear();
						ethernetPacket.setU2Packet(packet);
						this.parseEthernetFramePacket(fc);
						// determine frame type and build associated packet
						switch ((int) ethernetPacket.getFrameType()) {
							case EthernetFramePacket.IP_TYPE:
								ipPacket = this.getIPPacketClear();
								ipPacket.setPacket(ethernetPacket);
								break;
							default:
								break;
						}
						break;
					default:
						break;		
				}
				break;
			default:
				break;
		}
				
		
		
				
	}
	
	
	private Unified2RecordHeader getHeaderClear() {
		if (header == null) {
			header = new Unified2RecordHeader();
		} else {
			header.clear();
		}
		return header;		
	}
	
	private Unified2Packet getPacketClear() {
		if (packet == null) {
			packet = new Unified2Packet();			
		} else {
			packet.clear();
		}
		return packet;
	}
	
	private EthernetFramePacket getEthernetPacketClear() {
		if (ethernetPacket == null) {
			ethernetPacket = new EthernetFramePacket();			
		} else {
			ethernetPacket.clear();
		}
		return ethernetPacket;
	}
	
	private IPPacket getIPPacketClear() {
		if (ipPacket == null) {
			ipPacket = new IPPacket();			
		} else {
			ipPacket.clear();
		}
		return ipPacket;
	}
	
	public void readRecordHeader() {
		buf = ByteBuffer.allocate(HEADER_SIZE);
		buf.clear();
		try {
			int nread = 0;		
			do {
				nread = fc.read(buf);			
			} while (nread != -1 && buf.hasRemaining());
		} catch (Exception e) {
			e.printStackTrace();
		}
		buf.rewind();
		// parse out header
		header = this.getHeaderClear();	
		bytes4 = Utilities.clearBytes(bytes4);		
		// get type
		buf.get(bytes4, 0, TYPE_SIZE);
		header.setType(Utilities.unsignedIntToLong(bytes4));
		// clear buffer		
		bytes4 = Utilities.clearBytes(bytes4);	
		// get length		
		buf.get(bytes4, 0, LENGTH_SIZE);		
		header.setLength(Utilities.unsignedIntToLong(bytes4));
		// clear buffer
		bytes4 = Utilities.clearBytes(bytes4);
	}
	
	public void readPacketHeader(long recordLength) {
		buf = ByteBuffer.allocate(PACKET_HEADER_SIZE);
		buf.clear();
		try {
			int nread = 0;		
			do {
				nread = fc.read(buf);			
			} while (nread != -1 && buf.hasRemaining());
		} catch (Exception e) {
			e.printStackTrace();
		}
		buf.rewind();
		// parse out packet
		packet = this.getPacketClear();
		bytes4 = Utilities.clearBytes(bytes4);
		buf.get(bytes4, 0, SENSOR_ID_SIZE);
		// get sensor id
		packet.setSensor_id(Utilities.unsignedIntToLong(bytes4));
		bytes4 = Utilities.clearBytes(bytes4);
		// get event id
		buf.get(bytes4, 0, EVENT_ID_SIZE);
		packet.setEvent_id(Utilities.unsignedIntToLong(bytes4));
		bytes4 = Utilities.clearBytes(bytes4);
		// get seconds
		buf.get(bytes4, 0, EVENT_SEC_SIZE);
		packet.setEvent_second(Utilities.unsignedIntToLong(bytes4));
		bytes4 = Utilities.clearBytes(bytes4);
		// get packet seconds
		buf.get(bytes4, 0, PACKET_SEC_SIZE);
		packet.setPacket_second(Utilities.unsignedIntToLong(bytes4));
		bytes4 = Utilities.clearBytes(bytes4);
		// get packet mseconds
		buf.get(bytes4, 0, PACKET_MSEC_SIZE);
		packet.setPacket_microsecond(Utilities.unsignedIntToLong(bytes4));
		bytes4 = Utilities.clearBytes(bytes4);
		// get link type
		buf.get(bytes4, 0, LINK_TYPE_SIZE);
		packet.setLinktype(Utilities.unsignedIntToLong(bytes4));
		bytes4 = Utilities.clearBytes(bytes4);
		// get packet length
		buf.get(bytes4, 0, PACKET_LENGTH_SIZE);
		packet.setPacket_length(Utilities.unsignedIntToLong(bytes4));
		bytes4 = Utilities.clearBytes(bytes4);


	}		
	
	private void parseEthernetFramePacket(FileChannel fc) {
		buf = ByteBuffer.allocate((int)packet.packet_length);
		buf.clear();
		try {			
			int nread = 0;		
			do {
				nread = fc.read(buf);			
			} while (nread != -1 && buf.hasRemaining());
		} catch (Exception e) {
			e.printStackTrace();
		}
		buf.rewind();
		// parse out packet		
		bytes6 = Utilities.clearBytes(bytes6);
		// get dst mac address
		buf.get(bytes6, 0, (int) EthernetFramePacket.DST_SIZE);
		ethernetPacket.setEtherDestination(Utilities.sixBytesToLong(bytes6));
		bytes6 = Utilities.clearBytes(bytes6);
		// get src mac address
		buf.get(bytes6, 0, (int) EthernetFramePacket.SRC_SIZE);
		ethernetPacket.setEtherSource(Utilities.sixBytesToLong(bytes6));
		bytes6 = Utilities.clearBytes(bytes6);
		// get frame type
		bytes2 = Utilities.clearBytes(bytes2);
		buf.get(bytes2, 0, (int) EthernetFramePacket.FRAME_TYPE_SIZE);
		ethernetPacket.setFrameType(Utilities.unsignedShortToInt(bytes2));
		System.out.println("HI");
	}
	
	public static final int HEADER_SIZE = 8;
	public static final int PACKET_HEADER_SIZE = 28;
	public static final int TYPE_SIZE = 4;
	public static final int LENGTH_SIZE = 4;
	public static final int SENSOR_ID_SIZE = 4;
	public static final int EVENT_ID_SIZE = 4;
	public static final int EVENT_SEC_SIZE = 4;
	public static final int PACKET_SEC_SIZE = 4;
	public static final int PACKET_MSEC_SIZE = 4;
	public static final int LINK_TYPE_SIZE = 4;
	public static final int PACKET_LENGTH_SIZE = 4;

	public static final int ETHERNET_LINK = 1;
}
