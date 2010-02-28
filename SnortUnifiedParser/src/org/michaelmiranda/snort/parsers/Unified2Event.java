/**
 * 
 */
package org.michaelmiranda.snort.parsers;

/**
 * @author mikeymic
 *
 */
public class Unified2Event {
	
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
	public int getProtocol() {
		return protocol;
	}
	public void setProtocol(int protocol) {
		this.protocol = protocol;
	}
	public int getPacket_action() {
		return packet_action;
	}
	public void setPacket_action(int packetAction) {
		packet_action = packetAction;
	}
	public int getPad() {
		return pad;
	}
	public void setPad(int pad) {
		this.pad = pad;
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
	int protocol;
	int packet_action;
	int pad;

}
