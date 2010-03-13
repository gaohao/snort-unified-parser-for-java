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
 * Filename: EthernetFrame.java
 * Package: org.michaelmiranda.snort.parsers
 * Timestamp: Mar 5, 2010 10:03:56 PM
 * Author: Michael J. A. Miranda
 */
package org.michaelmiranda.snort.parsers;


/**
 * @author Michael J. A. Miranda
 *
 */
public class EthernetFramePacket implements SnortPacketInterface {
	
	
	/**
	 * @return the u2header
	 */
	public Unified2RecordHeader getU2header() {
		return u2header;
	}


	/**
	 * @param u2header the u2header to set
	 */
	public void setU2header(Unified2RecordHeader u2header) {
		this.u2header = u2header;
	}


	public void clear() {
		u2packet = null;		
	}
	
		
	/**
	 * @return the packet
	 */
	public Unified2Packet getU2Packet() {
		return u2packet;
	}
	/**
	 * @param packet the packet to set
	 */
	public void setU2Packet(Unified2Packet packet) {
		this.u2packet = packet;
	}

	/**
	 * @return the etherDestination
	 */
	public long getEtherDestination() {
		return etherDestination;
	}


	/**
	 * @param etherDestination the etherDestination to set
	 */
	public void setEtherDestination(long etherDestination) {
		this.etherDestination = etherDestination;
	}


	/**
	 * @return the etherSource
	 */
	public long getEtherSource() {
		return etherSource;
	}


	/**
	 * @param etherSource the etherSource to set
	 */
	public void setEtherSource(long etherSource) {
		this.etherSource = etherSource;
	}


	/**
	 * @return the frameType
	 */
	public long getFrameType() {
		return frameType;
	}


	/**
	 * @param frameType the frameType to set
	 */
	public void setFrameType(long frameType) {
		this.frameType = frameType;
	}
	
	public String toString() {
		String s = "";
		s += u2header.toString();
		s += u2packet.toString();
		s += "ETHER SRC: " + this.etherSource + "\n";
		s += "ETHER DST: " + this.etherDestination + "\n";
		s += "FRAME TYPE: " + this.frameType + "\n";
		return s;
	}
	
	private long etherDestination;
	private long etherSource;
	private long frameType;

	private Unified2RecordHeader u2header;
	private Unified2Packet u2packet;
	
	public static final long DST_SIZE = 6;
	public static final long SRC_SIZE = 6;
	public static final long FRAME_TYPE_SIZE = 2;
	public static final int IP_TYPE = 2048;
	
	
}
