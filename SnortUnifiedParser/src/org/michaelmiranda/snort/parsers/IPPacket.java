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
 * Filename: IPPacket.java
 * Package: org.michaelmiranda.snort.parsers
 * Timestamp: Mar 7, 2010 8:55:26 PM
 * Author: Michael J. A. Miranda
 */
package org.michaelmiranda.snort.parsers;

/**
 * @author Michael J. A. Miranda
 *
 */
public class IPPacket implements SnortPacketInterface {
	
	/**
	 * @return the ttl
	 */
	public short getTtl() {
		return ttl;
	}
	/**
	 * @param ttl the ttl to set
	 */
	public void setTtl(short ttl) {
		this.ttl = ttl;
	}
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
	 * @return the versionIhl
	 */
	public int getVersionIhl() {
		return versionIhl;
	}
	
	/**
	 * @param versionIhl the versionIhl to set
	 */
	public void setVersionIhl(int versionIhl) {
		this.versionIhl = versionIhl;
	}
	/**
	 * @return the tos
	 */
	public int getTos() {
		return tos;
	}
	/**
	 * @param tos the tos to set
	 */
	public void setTos(int tos) {
		this.tos = tos;
	}
	/**
	 * @return the len
	 */
	public long getLen() {
		return len;
	}
	/**
	 * @param len the len to set
	 */
	public void setLen(long len) {
		this.len = len;
	}
	/**
	 * @return the id
	 */
	public long getId() {
		return id;
	}
	/**
	 * @param id the id to set
	 */
	public void setId(long id) {
		this.id = id;
	}
	/**
	 * @return the flagFrag
	 */
	public long getFlagFrag() {
		return flagFrag;
	}
	/**
	 * @param flagFrag the flagFrag to set
	 */
	public void setFlagFrag(long flagFrag) {
		this.flagFrag = flagFrag;
	}
	/**
	 * @return the proto
	 */
	public short getProto() {
		return proto;
	}
	/**
	 * @param proto the proto to set
	 */
	public void setProto(short proto) {
		this.proto = proto;
	}
	
	/**
	 * @return the checksum
	 */
	public int getChecksum() {
		return checksum;
	}
	/**
	 * @param checksum the checksum to set
	 */
	public void setChecksum(int checksum) {
		this.checksum = checksum;
	}
	/**
	 * @return the ipSource
	 */
	public long getIpSource() {
		return ipSource;
	}
	/**
	 * @param ipSource the ipSource to set
	 */
	public void setIpSource(long ipSource) {
		this.ipSource = ipSource;
	}
	/**
	 * @return the ipDestination
	 */
	public long getIpDestination() {
		return ipDestination;
	}
	/**
	 * @param ipDestination the ipDestination to set
	 */
	public void setIpDestination(long ipDestination) {
		this.ipDestination = ipDestination;
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
		s += this.getPacket().toString();
		s += "IP VersionIHL: " + this.versionIhl + "\n";
		s += "IP TOS: " + this.tos + "\n";
		s += "IP Length: " + this.len + "\n";
		s += "IP ID: " + this.id + "\n";
		s += "IP Flag/Frag: " + this.flagFrag + "\n";
		s += "IP TTL: " + this.ttl + "\n";
		s += "IP Protocol: " + this.proto + "\n";
		s += "IP Chksum: " + this.checksum + "\n";
		s += "IP Source: " + this.ipSource + "\n";
		s += "IP Destination: " + this.ipDestination +"\n";
		
		return s;
	}
	
	private SnortPacketInterface packet;
	private int versionIhl;
	private int tos;
	private long len;
	private long id;
	private long flagFrag;
	private short ttl;
	private short proto;
	private int checksum;
	private long ipSource;
	private long ipDestination;
	
	public final static int VERSION_IHL_TOS_SIZE = 2;	
	public final static int LENGTH_SIZE = 2;
	public final static int ID_SIZE = 2;
	public final static int FLAG_FRAG_SIZE = 2;
	public final static int TTL_PROTO_SIZE = 2;
	public final static int CHKSUM_SIZE = 2;
	public final static int SRC_SIZE = 4;
	public final static int DST_SIZE = 4;
		

}
