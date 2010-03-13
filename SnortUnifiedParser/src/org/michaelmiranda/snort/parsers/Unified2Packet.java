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
 * Filename: Unified2Packet.java
 * Package: org.michaelmiranda.snort.parsers
 * Timestamp: Mar 5, 2010 10:03:56 PM
 * Author: Michael J. A. Miranda
 */
package org.michaelmiranda.snort.parsers;

/**
 * @author Michael J. A. Miranda
 *
 */
public class Unified2Packet {

	public long getSensor_id() {
		return sensor_id;
	}
	public void setSensor_id(long sensorId) {
		sensor_id = sensorId;
	}
	public long getEvent_id() {
		return event_id;
	}
	public void setEvent_id(long eventId) {
		event_id = eventId;
	}
	public long getEvent_second() {
		return event_second;
	}
	public void setEvent_second(long eventSecond) {
		event_second = eventSecond;
	}
	public long getPacket_second() {
		return packet_second;
	}
	public void setPacket_second(long packetSecond) {
		packet_second = packetSecond;
	}
	public long getPacket_microsecond() {
		return packet_microsecond;
	}
	public void setPacket_microsecond(long packetMicrosecond) {
		packet_microsecond = packetMicrosecond;
	}
	public long getLinktype() {
		return linktype;
	}
	public void setLinktype(long linktype) {
		this.linktype = linktype;
	}
	public long getPacket_length() {
		return packet_length;
	}
	public void setPacket_length(long packetLength) {
		packet_length = packetLength;
	}
	public short getPacket_data() {
		return packet_data;
	}
	public void setPacket_data(short packetData) {
		packet_data = packetData;
	}
	
	public void clear() {
		this.setSensor_id(0);
		this.setEvent_id(0);
		this.setEvent_second(0);
		this.setPacket_second(0);
		this.setPacket_microsecond(0);
		this.setLinktype(0);
		this.setPacket_length(0);
		this.setPacket_data((short)0);
	}
	
	public String toString() {
		String s = "";
		s += "U2 Sensor ID: " + this.sensor_id + "\n";
		s += "U2 Event ID: " + this.event_id + "\n";
		s += "U2 Event Seconds: " + this.event_second + "\n";
		s += "U2 Packet Seconds: " + this.packet_second + "\n";
		s += "U2 Packet MicroSeconds: " + this.packet_microsecond + "\n";
		s += "U2 Link Type: " + this.linktype + "\n";
		s += "U2 Packet Length: " + this.packet_length + "\n";
		s += "U2 Packet Data: " + this.packet_data + "\n";
		return s;
	}
	
	long sensor_id;
	long event_id;
	long event_second;
	long packet_second;
	long packet_microsecond;
	long linktype;
	long packet_length;
	short packet_data;
	
	
	
}
