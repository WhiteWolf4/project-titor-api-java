package com.ww4projects.projtitor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;

public class Shinfi {
	
	private static final int AES_KEYLENGTH = 16;
	
	RSAPrivateKey rsa_private_key;
	
	/* Constructor */
	public Shinfi( InputStream pem ) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		Security.addProvider(new BouncyCastleProvider());
		
		PemReader pr = new PemReader( new InputStreamReader(pem) );
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
		byte[] content = pr.readPemObject().getContent();
		pr.close();
		
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(content);
		this.rsa_private_key = (RSAPrivateKey) keyFactory.generatePrivate(ks);
		
	}
	
	/* Decryptors */
	
	public void decrypt( String filepath , String hashfile ) throws IOException, InvalidKeyException {
		
		this.decrypt(
				new FileInputStream(filepath),
				new FileInputStream(hashfile)
				);
		
	}
	
	public byte[] decrypt( InputStream fileis, InputStream hashis ) throws IOException, InvalidKeyException {
		
		String hash = new String(this.readISAsBytes(hashis));
		byte[] aeshash = this.compressHashToAES(hash);
		byte[] iv = new byte[AES_KEYLENGTH];		
		byte[] file = this.readISAsBytes(fileis);
		
		byte[] final_file = null;
			
		try {
			
			byte[] dfile = this.decryptAES( file , aeshash , iv);
			InputStream stream = new ByteArrayInputStream(this.GZIPDecompress(dfile));
			
			MetaSchema pkey = this.readEntry(stream);
			MetaSchema efile = this.readEntry(stream);
			
			//this.validate_hash( efile , hash );
			
			byte[] dec_pkey = this.decryptPrivateKey( pkey );
			final_file = this.decryptAES(efile.body, dec_pkey, efile.encryption_extras );	
			
			
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			fileis.close();
			hashis.close();			
		}			
		
		return final_file;
		
	}
	
	/* Private Methods */

	private byte[] readISAsBytes( InputStream is ) throws IOException {
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		IOUtils.copy( is, baos );
		
		return baos.toByteArray();
		
	}
	
	private byte[] compressHashToAES( String hash ) {
				
		byte[] _hash = new byte[AES_KEYLENGTH];
		byte[] mask = this.rsa_private_key.getModulus().subtract(this.rsa_private_key.getPrivateExponent()).toByteArray();

		for( int i = 0; i < hash.length(); ++i ) _hash[i % AES_KEYLENGTH] ^= ((hash.charAt(i)) + ( mask[ i < mask.length ? (mask.length-1-i) : 0 ] & 0xFF));
		
		return _hash;		
		
	}
	
	private byte[] decryptAES( byte[] file, byte[] key, byte[] iv ) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		SecretKeySpec pkey = new SecretKeySpec( key, "AES" );
		IvParameterSpec ivs = new IvParameterSpec( iv );
		
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		cipher.init( Cipher.DECRYPT_MODE, pkey, ivs );
		
		return cipher.doFinal( file );

	}
	
	private byte[] GZIPDecompress( byte[] compressed ) throws IOException {
		
		GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(compressed));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		IOUtils.copy( gis,  baos);
		
		return baos.toByteArray();
		
	}	
	
	private MetaSchema readEntry( InputStream stream ) throws IOException {
		
		MetaSchema entry = new MetaSchema();
		
		stream.read(entry.filename,0,entry.filename.length);
		stream.read(entry.size,0,entry.size.length);
		stream.read(entry.encryption_extras,0,entry.encryption_extras.length);
		entry.body = new byte[entry.getSize()];
		stream.read(entry.body,0,entry.body.length);
		
		return entry;
		
	}
	
	/*private void validate_hash(MetaSchema efile, String hash) {
		
		// Future method to validate SHA-512. Java by default not supports this algorithm.
		
	}*/
	
	private byte[] decryptPrivateKey(MetaSchema entry) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, this.rsa_private_key);
		return cipher.doFinal(Base64.getDecoder().decode(entry.body));
		
	}
	
	

}
