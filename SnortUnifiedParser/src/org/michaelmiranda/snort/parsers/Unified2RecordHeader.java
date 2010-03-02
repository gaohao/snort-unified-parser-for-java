/**
 * 
 */
package org.michaelmiranda.snort.parsers;

/**
 * @author mikeymic
 *
 */
public class Unified2RecordHeader {

	public long getType() {
		return type;
	}

	public void setType(long type) {
		this.type = type;
	}

	public long getLength() {
		return length;
	}

	public void setLength(long length) {
		this.length = length;
	}
	
	public void clear() {
		this.length = 0;
		this.type = 0;
	}

	long length;
	long type;
	
}
