/**
 * 
 */
package org.michaelmiranda.snort.parsers;

import java.io.*;

/**
 * @author mikeymic
 *
 *s
 */
public class SnortUnified {

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
		
		DataInputStream inputStream = Utilities.getBinaryFileStream(filename);
		
		
	}
	
	

}
