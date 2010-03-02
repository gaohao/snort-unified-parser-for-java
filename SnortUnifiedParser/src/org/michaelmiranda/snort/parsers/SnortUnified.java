/**
 * 
 */
package org.michaelmiranda.snort.parsers;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;

/**
 * @author mikeymic
 *
 */
public class SnortUnified {

	private ByteBuffer buf;
	private ByteBuffer buf_tmp;
	private Unified2RecordHeader header;
	
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
		this.readLogFileHeader(fc);		
	}
		
	
	private Unified2RecordHeader getHeaderClear() {
		if (header == null) {
			header = new Unified2RecordHeader();
		} else {
			header.clear();
		}
		return header;		
	}
	
	public void readLogFileHeader(FileChannel fc) {
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
		byte[] b = new byte[4];
		// get type
		buf.get(b, this.startByteIndex, 4);
		header.type = Utilities.unsignedIntToLong(b);
		// clear buffer
		java.util.Arrays.fill(b, 0, b.length, new Integer(0).byteValue());
		// get length
		buf.get(b);
		header.length = Utilities.unsignedIntToLong(b);
		// clear buffer
		java.util.Arrays.fill(b, 0, b.length, new Integer(0).byteValue());
		
	}
	
	public static final int HEADER_SIZE = 8;
	public static final int TYPE_SIZE = 4;
	public static final int LENGTH_SIZE = 4;
	

}
