/**
 * 
 */
package org.michaelmiranda.snort.parsers;

/**
 * @author mikeymic
 *
 */
public class Unified2Event6_v2 {
	
	long sensor_id;
	long event_id;
	long event_second;
	long event_microsecond;
	long signature_id;
	long generator_id;
	long signature_revision;
	long classification_id;
	long priority_id;
	IPv6Address ip_source;
	IPv6Address ip_destination;
	long sport_itype;
	long dport_icode;
	int protocol;
	int packet_action;
	int pad;
	
	class IPv6Address {
		short addr;
	}

}
