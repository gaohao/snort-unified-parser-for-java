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
 * Filename: Utilities.java
 * Package: org.michaelmiranda.snort.parsers
 * Timestamp: Mar 5, 2010 10:03:56 PM
 * Author: Michael J. A. Miranda
 */
package org.michaelmiranda.snort.parsers;

import java.io.*;
import java.net.InetAddress;
import java.nio.channels.*;
import java.nio.*;

/**
 * @author Michael J. A. Miranda
 *
 */
public class Utilities {

	public static DataInputStream getBinaryFileStream(String filename) {
		DataInputStream inputStream = null;
		try {
			FileInputStream inputFile = new FileInputStream(filename);
			inputStream = new DataInputStream(inputFile);
			
		} catch (FileNotFoundException e) {			
			e.printStackTrace();
		}
		return inputStream;
		
	}
	
	public static FileChannel getBinaryFilechannel(String filename) {
		FileChannel fc = null;
		try {
			RandomAccessFile f = new RandomAccessFile(new File(filename), "r");
			fc = f.getChannel();						
		} catch (Exception e) {
			e.printStackTrace();
		}
		return fc;
	}
	
	public static final long unsignedIntToLong(byte[] b) 
	{
	    long l = 0;
	    l |= b[0] & 0xFF;
	    l <<= 8;
	    l |= b[1] & 0xFF;
	    l <<= 8;
	    l |= b[2] & 0xFF;
	    l <<= 8;
	    l |= b[3] & 0xFF;
	    return l;
	}
	    
	public static final int unsignedShortToInt(byte[] b) 
	{
	    int i = 0;
	    i |= b[0] & 0xFF;
	    i <<= 8;
	    i |= b[1] & 0xFF;
	    return i;
	}
	
	public static final long sixBytesToLong(byte[] b) 
	{
	    long l = 0;
	    l |= b[0] & 0xFF;
	    l <<= 8;
	    l |= b[1] & 0xFF;
	    l <<= 8;
	    l |= b[2] & 0xFF;
	    l <<= 8;
	    l |= b[3] & 0xFF;
	    l <<= 8;
	    l |= b[4] & 0xFF;
	    l <<= 8;
	    l |= b[5] & 0xFF;
	    return l;
	}
	
	public static byte[] clearBytes(byte[] b) {
		java.util.Arrays.fill(b, 0, b.length, new Integer(0).byteValue());
		return b;
	}
	
	
	private static byte[] bArray = new byte[4];
    private static ByteBuffer bBuffer  = ByteBuffer.wrap(bArray);
    private static IntBuffer lBuffer =  bBuffer.asIntBuffer();
    
	public static byte[] longToByteArray(long l) {
		lBuffer.clear();
        lBuffer.put(0, (int) l);        
        return bArray;
	}
	
	public static String longToIPAddress(long l) {
		String ipAddressString = "";
		try {
			ipAddressString = InetAddress.getByAddress(Utilities.longToByteArray(l)).getHostAddress();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ipAddressString;
		
	}

	
}
