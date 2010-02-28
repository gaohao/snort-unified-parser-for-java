/**
 * 
 */
package org.michaelmiranda.snort.parsers;

/**
 * @author mikeymic
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
		return packet_lenght;
	}
	public void setPacket_length(long packetLenght) {
		packet_lenght = packetLenght;
	}
	public short getPacket_data() {
		return packet_data;
	}
	public void setPacket_data(short packetData) {
		packet_data = packetData;
	}
	
	long sensor_id;
	long event_id;
	long event_second;
	long packet_second;
	long packet_microsecond;
	long linktype;
	long packet_lenght;
	short packet_data;
	
	
	
}
