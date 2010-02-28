/**
 * 
 */
package org.michaelmiranda.snort.parsers;

import java.io.*;

/**
 * @author mikeymic
 *
 */
public class Utilities {

	public static DataInputStream getBinaryFileStream(String filename) {
		
		try {
			FileInputStream inputFile = new FileInputStream(filename);
			DataInputStream inputStream = new DataInputStream(inputFile);
			return inputStream;
		} catch (FileNotFoundException e) {			
			e.printStackTrace();
		}
		return null;
		
	}
	
}
