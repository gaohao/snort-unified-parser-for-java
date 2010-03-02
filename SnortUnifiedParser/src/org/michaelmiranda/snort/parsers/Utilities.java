/**
 * 
 */
package org.michaelmiranda.snort.parsers;

import java.io.*;
import java.nio.channels.*;

/**
 * @author mikeymic
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

	
}
