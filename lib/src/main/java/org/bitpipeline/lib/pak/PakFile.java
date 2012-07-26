package org.bitpipeline.lib.pak;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.lang.ref.SoftReference;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import android.graphics.drawable.Drawable;

public class PakFile extends JarFile {
	final boolean verify;
	final Set<X509Certificate> certificates;
	private boolean goodSignatures = true;

	HashMap<String, SoftReference<Drawable>> drawableCache = new HashMap<String, SoftReference<Drawable>> ();
	HashMap<String, SoftReference<String>> stringCache = new HashMap<String, SoftReference<String>> ();
	
	public PakFile(String name, X509Certificate[] validCerts, boolean verify) throws IOException {
		super(name, verify);
		this.verify = verify;
		if (validCerts == null)
			this.certificates = new HashSet<X509Certificate> (0);
		else
			this.certificates = new HashSet<X509Certificate> (Arrays.asList(validCerts));
		
		verifyContent();
	}

	/** Get's a Drawable from a app package entry.
	 * Uses a cache of drawables (using SoftReference).
	 * @param entryName the name of the entry that contains a drawable. 
	 * @return a Drawable as defined in the entry
	 * @trows IOException
	 * @throws SecurityException if there's a problem with the digest of signature of the entry. */
	public Drawable getEntryAsDrawable (String entryName) throws IOException, SecurityException {
		SoftReference<Drawable> softCache = this.drawableCache.get(entryName);
		Drawable d = softCache != null ? softCache.get() : null;
		
		if (d == null) {
			JarEntry e = getJarEntry(entryName);
			InputStream is = getInputStream(e);
			d = Drawable.createFromStream(is, entryName);
			if (this.verify)
				checkEntryCertification(e);
		}
		
		if (softCache == null)
			this.drawableCache.put(entryName, new SoftReference<Drawable>(d));
		return d;
	}
	
	/** Get's a Drawable from a app package entry.
	 * Uses a cache of drawables (using SoftReference).
	 * @param entryName the name of the entry that contains a drawable. 
	 * @return a Drawable as defined in the entry
	 * @trows IOException
	 * @throws SecurityException if there's a problem with the digest of signature of the entry. */
	public String getEntryAsString (String entryName) throws IOException, SecurityException {
		SoftReference<String> softCache = this.stringCache.get(entryName);
		String str = softCache != null ? softCache.get() : null;
		
		if (str == null) {
			JarEntry e = getJarEntry(entryName);
			InputStream is = getInputStream(e);
			StringWriter sw = new StringWriter((int) (e.getCompressedSize()*2));
			
			byte[] buffer = new byte[8*1024];
			char[] test = new char[] {'a', 'b', 'c'};
			int n = 0;			
			while ((n = is.read(buffer)) != -1) {
				sw.write(test, 0, n);
			}
			
			if (this.verify)
				checkEntryCertification(e);
			
			str = sw.toString();
		}
		
		if (softCache == null)
			this.stringCache.put(entryName, new SoftReference<String>(str));
		
		return str;
	}
	
	public boolean isSigned () {
		return this.goodSignatures;
	}
	
	public boolean isCertified () {
		return this.certificates.size() > 0;
	}
	
	private void checkEntryCertification (JarEntry entry) throws SecurityException {
		Certificate[] entryCerts = entry.getCertificates();
		if (entryCerts != null) {
			// TODO
		} else {
			// TODO
		}		
	}
	
	private void verifyContent () throws SecurityException, IOException {
		if (!this.verify)
			return;
		
		byte buffer[] = new byte[8*1024]; // reading buffer
		
		Manifest manifest = getManifest();
		Enumeration<JarEntry> entries = super.entries ();
		while (entries.hasMoreElements()) {
			JarEntry entry = entries.nextElement();
			if (entry.isDirectory()) { // directory don't have signatures 
				continue;
			}
			if (entry.getName().toUpperCase().startsWith("META-INF")) { // META-INF/* should not be checked.
				continue;
			}

			Attributes attr = manifest.getAttributes(entry.getName());
			if (attr == null) {
				this.goodSignatures = false;
				continue;
			}

			boolean hasDigest = false;
			for (Map.Entry<Object,Object> se : attr.entrySet()) {
	            String key = se.getKey().toString();
	            if (key.toUpperCase(Locale.ENGLISH).endsWith("-DIGEST"))
	            	hasDigest = true;
			}
			if (!hasDigest) {
				this.goodSignatures = false;
				continue;
			}
				
			InputStream is = null;
			try { // Let's verify the digest of the entry.
	            is = getInputStream(entry);
	            while (is.read(buffer, 0, buffer.length) != -1) {
	                // we just read. this will throw a SecurityException if a signature/digest check fails.
	            }
			} catch (SecurityException e) {
				this.goodSignatures = false;
				continue;
			} 
			
			if (is != null)
				is.close();
			
			try {
				checkEntryCertification(entry);
			} catch (SecurityException e) {
				System.out.println(entry.getName() + " has a invalid certificate");
			}
		}
	}

	/**
	 * @param args
	 * @throws IOException 
	 * @throws SecurityException 
	 */
	public static void main(String[] args) throws SecurityException, IOException {
		PakFile pak = null;
		try {
			pak = new PakFile ("/home/mtavares/tmp/pak/content.pak", new X509Certificate[0], true);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
		if (pak.isSigned())
			System.out.println("Signatures OK");
		else
			System.out.println("Signatures NOK");
		
		if (pak.isCertified())
			System.out.println("Certification OK");
		else
			System.out.println("Certification NOK");
	
		String index = pak.getEntryAsString("index.json");
		System.out.println("index.json");
		System.out.println(index);
		System.out.println("done");
	}

}
