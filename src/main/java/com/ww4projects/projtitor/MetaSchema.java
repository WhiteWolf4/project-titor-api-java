package com.ww4projects.projtitor;

public class MetaSchema {
	
	public byte[] filename = new byte[100];
	public byte[] size = new byte[4];;
	public byte[] encryption_extras = new byte[16];
	public byte[] body;
	
	private int convertHexToInt( byte[] hxint ) {
		int value = 0;
		for(int i=0; i < hxint.length; ++i) value += ( ( hxint[(hxint.length-1)-i] & 0xFF )  << (i*8) );
		return value;
	}
	
	public int getSize() {
		return convertHexToInt(this.size);
	}
	
	public String getFilename() {
		return new String(this.filename);
	}

}
