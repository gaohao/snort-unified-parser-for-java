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
 * Filename: Unified2Event.java
 * Package: org.michaelmiranda.snort.parsers
 * Timestamp: Mar 5, 2010 10:03:56 PM
 * Author: Michael J. A. Miranda
 */
package org.michaelmiranda.snort.parsers;

/**
 * @author Michael J. A. Miranda
 *
 */
public class Unified2Event implements SnortPacketInterface {
	
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
	public long getEvent_microsecond() {
		return event_microsecond;
	}
	public void setEvent_microsecond(long eventMicrosecond) {
		event_microsecond = eventMicrosecond;
	}
	public long getSignature_id() {
		return signature_id;
	}
	public void setSignature_id(long signatureId) {
		signature_id = signatureId;
	}
	public long getGenerator_id() {
		return generator_id;
	}
	public void setGenerator_id(long generatorId) {
		generator_id = generatorId;
	}
	public long getSignature_revision() {
		return signature_revision;
	}
	public void setSignature_revision(long signatureRevision) {
		signature_revision = signatureRevision;
	}
	public long getClassification_id() {
		return classification_id;
	}
	public void setClassification_id(long classificationId) {
		classification_id = classificationId;
	}
	public long getPriority_id() {
		return priority_id;
	}
	public void setPriority_id(long priorityId) {
		priority_id = priorityId;
	}
	public long getIp_source() {
		return ip_source;
	}
	public void setIp_source(long ipSource) {
		ip_source = ipSource;
	}
	public long getIp_destination() {
		return ip_destination;
	}
	public void setIp_destination(long ipDestination) {
		ip_destination = ipDestination;
	}
	public long getSport_itype() {
		return sport_itype;
	}
	public void setSport_itype(long sportItype) {
		sport_itype = sportItype;
	}
	public long getDport_icode() {
		return dport_icode;
	}
	public void setDport_icode(long dportIcode) {
		dport_icode = dportIcode;
	}
	public short getProtocol() {
		return protocol;
	}
	public void setProtocol(short protocol) {
		this.protocol = protocol;
	}
	public short getPacket_action() {
		return packet_action;
	}
	public void setPacket_action(short packetAction) {
		packet_action = packetAction;
	}
	public int getPad() {
		return pad;
	}
	public void setPad(int pad) {
		this.pad = pad;
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
		s += "Event SensorID: " + this.sensor_id + "\n";
		return s;		
	}
	
	long sensor_id;
	long event_id;
	long event_second;
	long event_microsecond;
	long signature_id;
	long generator_id;
	long signature_revision;
	long classification_id;
	long priority_id;
	long ip_source;
	long ip_destination;
	long sport_itype;
	long dport_icode;
	short protocol;
	short packet_action;
	int pad;
	

}
