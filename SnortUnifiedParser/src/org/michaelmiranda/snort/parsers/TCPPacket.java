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
 * Filename: TCPPacket.java
 * Package: org.michaelmiranda.snort.parsers
 * Timestamp: Mar 7, 2010 8:48:55 PM
 * Author: Michael J. A. Miranda
 */
package org.michaelmiranda.snort.parsers;

/**
 * @author Michael J. A. Miranda
 *
 */
public class TCPPacket implements SnortPacketInterface {

	
	/**
	 * @return the packet
	 */
	public SnortPacketInterface getPacket() {
		return packet;
	}
	/**
	 * @param packet the packet to set
	 */
	public void setPacket(SnortPacketInterface packet) {
		this.packet = packet;
	}
	/**
	 * @return the portSource
	 */
	public long getPortSource() {
		return portSource;
	}
	/**
	 * @param portSource the portSource to set
	 */
	public void setPortSource(long portSource) {
		this.portSource = portSource;
	}
	/**
	 * @return the portDestination
	 */
	public long getPortDestination() {
		return portDestination;
	}
	/**
	 * @param portDestination the portDestination to set
	 */
	public void setPortDestination(long portDestination) {
		this.portDestination = portDestination;
	}
	/**
	 * @return the sequence
	 */
	public long getSequence() {
		return sequence;
	}
	/**
	 * @param sequence the sequence to set
	 */
	public void setSequence(long sequence) {
		this.sequence = sequence;
	}
	/**
	 * @return the ack
	 */
	public long getAck() {
		return ack;
	}
	/**
	 * @param ack the ack to set
	 */
	public void setAck(long ack) {
		this.ack = ack;
	}
	/**
	 * @return the offset
	 */
	public long getOffset() {
		return offset;
	}
	/**
	 * @param offset the offset to set
	 */
	public void setOffset(long offset) {
		this.offset = offset;
	}
	/**
	 * @return the win
	 */
	public long getWin() {
		return win;
	}
	/**
	 * @param win the win to set
	 */
	public void setWin(long win) {
		this.win = win;
	}
	/**
	 * @return the chksum
	 */
	public long getChksum() {
		return chksum;
	}
	/**
	 * @param chksum the chksum to set
	 */
	public void setChksum(long chksum) {
		this.chksum = chksum;
	}
	/**
	 * @return the urg_p
	 */
	public long getUrg_p() {
		return urg_p;
	}
	/**
	 * @param urgP the urg_p to set
	 */
	public void setUrg_p(long urgP) {
		urg_p = urgP;
	}
	/**
	 * @return the payload
	 */
	public String getPayload() {
		return payload;
	}
	/**
	 * @param payload the payload to set
	 */
	public void setPayload(String payload) {
		this.payload = payload;
	}

	/* (non-Javadoc)
	 * @see org.michaelmiranda.snort.parsers.SnortPacketInterface#clear()
	 */
	@Override
	public void clear() {
		// TODO Auto-generated method stub
		
	}
	
	
	public String toString() {
		String s = "";
		s += this.packet.toString();
		s += "TCP Port Source: " + this.portSource + "\n";
		s += "TCP Port Destination: " + this.portDestination + "\n";
		s += "TCP Sequence: " + this.sequence + "\n";
		s += "TCP Ack: " + this.ack + "\n";
		s += "TCP Offset: " + this.offset + "\n";
		s += "TCP Window: " + this.win + "\n";
		s += "TCP Chksum: " + this.chksum + "\n";
		s += "TCP URG_P: " + this.urg_p + "\n";
		return s;
	}
	
	private SnortPacketInterface packet;
	private long portSource;
	private long portDestination;
	private long sequence;
	private long ack;
	private long offset;
	private long win;
	private long  chksum;
	private long urg_p;
	private String payload;
	
	public static final int PORT_SIZE = 2;
	public static final int SEQ_SIZE = 4;
	public static final int ACK_SIZE = 4;
	public static final int OFFSET_SIZE = 2;
	public static final int WIN_SIZE = 2;
	public static final int CHKSUM_SIZE = 2;
	public static final int URGP_SIZE = 2;

	
	
}
