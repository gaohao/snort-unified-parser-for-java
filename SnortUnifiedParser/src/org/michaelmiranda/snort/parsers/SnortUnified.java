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

	private ByteBuffer buf;
	private byte[] bytes1;
	private byte[] bytes2;
	private byte[] bytes4;
	private byte[] bytes6;
	
	
	private Unified2RecordHeader header;
	private Unified2Packet packet;
	
	public int startByteIndex = 0;
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String f = "D:\\temp\\snort2.log.1267172679";
		SnortUnified su = new SnortUnified();
		su.parse(f);
	}
	
	
	public void parse(String filename) {
		
		//DataInputStream inputStream = Utilities.getBinaryFileStream(filename);
		FileChannel fc = Utilities.getBinaryFilechannel(filename);
		this.readRecordHeader(fc);
		switch ((int)header.getType()) {
			// Snort Event Record
			case 7:
				break;
			// IPv4 Packet Record
			case 2:
				this.readPacketHeader(fc, header.getLength());
				break;
			default:
				break;
		}
				
	}
		
	public SnortUnified() {
		bytes1 = new byte[1];
		bytes2 = new byte[2];
		bytes4 = new byte[4];
		bytes6 = new byte[6];
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
	
	public void readRecordHeader(FileChannel fc) {
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
		buf.get(bytes4, this.startByteIndex, TYPE_SIZE);
		header.setType(Utilities.unsignedIntToLong(bytes4));
		// clear buffer		
		bytes4 = Utilities.clearBytes(bytes4);	
		// get length		
		buf.get(bytes4, 0, LENGTH_SIZE);		
		header.setLength(Utilities.unsignedIntToLong(bytes4));
		// clear buffer
		bytes4 = Utilities.clearBytes(bytes4);		
	}
	
	public void readPacketHeader(FileChannel fc, long recordLength) {
		buf = ByteBuffer.allocate((int)header.length);
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
	
	public static final int HEADER_SIZE = 8;
	public static final int TYPE_SIZE = 4;
	public static final int LENGTH_SIZE = 4;
	public static final int SENSOR_ID_SIZE = 4;
	public static final int EVENT_ID_SIZE = 4;
	public static final int EVENT_SEC_SIZE = 4;
	public static final int PACKET_SEC_SIZE = 4;
	public static final int PACKET_MSEC_SIZE = 4;
	public static final int LINK_TYPE_SIZE = 4;
	public static final int PACKET_LENGTH_SIZE = 4;

}
