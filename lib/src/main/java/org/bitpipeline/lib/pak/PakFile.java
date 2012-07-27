package org.bitpipeline.lib.pak;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.lang.ref.SoftReference;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
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
	final Set<Certificate> trustedCertificates;
	boolean acceptAllCertificates;
	private boolean allSigned = false;
	private boolean allCertificated = false;
	private boolean tampered = false;

	public interface PakEntryReader<T> {
		void readEntry (String entryName, InputStream is);
		T getEntry ();
	}
	
	HashMap<String, SoftReference<Drawable>> drawableCache = new HashMap<String, SoftReference<Drawable>> ();
	HashMap<String, SoftReference<String>> stringCache = new HashMap<String, SoftReference<String>> ();
	
	public PakFile(String name, boolean verify) throws IOException {
		this (name, new HashSet<Certificate> (0), verify);
	}

	public PakFile(String name, Certificate[] validCerts, boolean verify) throws IOException {
		this (name, Arrays.asList(validCerts), verify);
	}

	public PakFile(String name, Certificate validCert, boolean verify) throws IOException {
		this (name, Arrays.asList (new Certificate[]{validCert}), verify);
	}
	
	public PakFile(String name, Collection<? extends Certificate> validCerts, boolean verify) throws IOException {
		super(name, verify);
		this.verify = verify;
		if (validCerts.size () == 0) {
			this.trustedCertificates = new HashSet<Certificate> (0);
			this.acceptAllCertificates = true;
		} else {
			this.trustedCertificates = new HashSet<Certificate> (validCerts);
			this.acceptAllCertificates = false;
		}
		
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
			Reader isReader = new InputStreamReader (getInputStream(e));
			StringWriter sw = new StringWriter((int) (e.getCompressedSize()*2));
			
			char[] buffer = new char[8*1024];
			int n = 0;			
			while ((n = isReader.read(buffer)) != -1) {
				sw.write(buffer, 0, n);
			}
			
			str = sw.toString();
		}
		
		if (softCache == null)
			this.stringCache.put(entryName, new SoftReference<String>(str));
		
		return str;
	}
	
	public boolean isSigned () {
		return this.allSigned;
	}
	
	/** Check if all the content of the packages is well certified.
	 * @return <tt>true</tt> if all the content of the package is certified with recognized certificates, <tt>false</tt> otherwise. */
	public boolean isCertified () {
		return this.allCertificated;
	}
	
	public boolean isTampered () {
		return this.tampered;
	}
	
	private boolean checkEntryCertification (JarEntry entry) throws SecurityException {
		Certificate[] entryCerts = entry.getCertificates();
		if (entryCerts != null) {
			if (this.acceptAllCertificates)
				return true;

			for (Certificate c : entryCerts) {
				if (PakFile.isTrusted (c, this.trustedCertificates))
					return true;
			}
			return false;
		}
		return false;
	}
	
	/** Check if a certificate is trusted.
	 * @param cert is the X509 certificate to check for trust
	 * @param trustedCert is the set of certificates that are trusted. */
	public static boolean isTrusted (Certificate cert, Set<Certificate> trustedCerts) {
		if (!(cert instanceof X509Certificate))
			return false;
		X509Certificate x509cert = (X509Certificate) cert;
		
		Principal certSubjectDN = x509cert.getSubjectDN ();
		if (certSubjectDN == null)
			return false;
		
		for (Certificate trustedCert : trustedCerts) {
			if (cert.equals (trustedCert))
				return true;
		}
		return false;
	}
	
	/** Verify the content of the pak file. */
	private void verifyContent () throws SecurityException, IOException {
		if (!this.verify)
			return;
		
		byte buffer[] = new byte[8*1024]; // reading buffer
		
		Manifest manifest = getManifest();
		Enumeration<JarEntry> entries = super.entries ();
		this.allCertificated = true;
		this.allSigned = true;
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
				this.allSigned = false;
				continue;
			}

			boolean hasDigest = false;
			for (Map.Entry<Object,Object> se : attr.entrySet()) {
	            String key = se.getKey().toString();
	            if (key.toUpperCase(Locale.ENGLISH).endsWith("-DIGEST"))
	            	hasDigest = true;
			}
			if (!hasDigest) {
				this.allSigned = false;
				continue;
			}
				
			InputStream is = null;
			try { // Let's verify the digest of the entry.
	            is = getInputStream(entry);
	            while (is.read(buffer, 0, buffer.length) != -1) {
	                // we just read. this will throw a SecurityException if a signature/digest check fails.
	            }
			} catch (SecurityException e) {
				this.tampered = true;
				continue;
			} 
			
			if (is != null)
				is.close();
			
			try {
				this.allCertificated &= checkEntryCertification(entry); 
			} catch (SecurityException e) {
				System.out.println(entry.getName() + " has a invalid certificate");
			}
		}
		this.allCertificated &= this.allSigned;
	}
}
