/**
 * Copyright 2012 J. Miguel P. Tavares
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ***************************************************************************/
package org.bitpipeline.lib.pak;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.lang.ref.SoftReference;
import java.security.cert.Certificate;
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

/** A class that makes it easy to use pak files. Pak files are zip files and are a easy way to distribute content. */
public class PakFile extends JarFile {
	final boolean verify;
	final Set<Certificate> trustedCertificates;
	boolean acceptAllCertificates;
	private boolean allSigned = false;
	private boolean allCertificated = false;
	private boolean tampered = false;

	private HashMap<String, SoftReference<Object>> cache = new HashMap<String, SoftReference<Object>> ();
		
	/** Opens a pak file with the specified name and accepting any certificate for validation.
	 * @param name the filename of the pak file  
	 * @param verify whether or not to verify the pak file if it is signed*/
	public PakFile(String name, boolean verify) throws IOException {
		this (name, new HashSet<Certificate> (0), verify);
	}

	/** Open a pak file.
	 * If the validCerts don't contain any certificate (sieze() = 0) then the
	 * PakFile will accept all the certificates presented in the file but content
	 * still has to be certified.
	 * @param name the filename of the pak file 
	 * @param validCerts is the certificates that are accepted as valid
	 * @param verify whether or not to verify the pak file if it is signed */
	public PakFile(String name, Certificate[] validCerts, boolean verify) throws IOException {
		this (name, Arrays.asList(validCerts), verify);
	}

	/** Opens a pak file.
	 * @param name the filename of the pak file 
	 * @param validCert is the certificate that is accepted as valid
	 * @param verify whether or not to verify the pak file if it is signed */
	public PakFile(String name, Certificate validCert, boolean verify) throws IOException {
		this (name, Arrays.asList (new Certificate[]{validCert}), verify);
	}
	
	/** Opens a pak file.
	 * If the validCerts don't contain any certificate (sieze() = 0) then the
	 * PakFile will accept all the certificates presented in the file but content
	 * still has to be certified.
	 * @param name the filename of the pak file 
	 * @param validCerts is the certificates that are accepted as valid
	 * @param verify whether or not to verify the pak file if it is signed */
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
	
	
	/** Get's a entry from the pak, using a reader to convert it to the desired object.
	 * Uses a cache of drawables (using SoftReference).
	 * @param entryName the name of the entry that contains a drawable. 
	 * @return The 
	 * @throws IOException 
	 * @throws SecurityException if there's a problem with the digest of signature of the entry. */
	public PakEntryReader<?> getEntryAs (String entryName, PakEntryReader<?> reader) throws IOException {
		SoftReference<Object> softCache = this.cache.get(entryName);
		Object cacheObj = softCache != null ? softCache.get() : null;
		
		if (cacheObj != null) {
			if (reader.setResult (cacheObj))
				return reader;
		}
		
		JarEntry e = getJarEntry(entryName);
		InputStream is = getInputStream(e);
		
		reader.readEntry (entryName, is);
		cacheObj = reader.getEntry ();
		
		this.cache.put(entryName, new SoftReference<Object>(cacheObj)); // add it to the cache
		
		return reader;
	}
	
	/** Get's a Drawable from a app package entry.
	 * Uses a cache of drawables (using SoftReference).
	 * @param entryName the name of the entry that contains a drawable. 
	 * @return a Drawable as defined in the entry
	 * @trows IOException
	 * @throws SecurityException if there's a problem with the digest of signature of the entry. */
	public String getEntryAsString (String entryName) throws IOException, SecurityException {
		SoftReference<Object> softCache = this.cache.get(entryName);
		Object cacheObj = softCache != null ? softCache.get() : null;
		
		String str;
		if (cacheObj != null && (cacheObj instanceof String)) { // Yeah! Still alive on cache!
			str = (String) cacheObj;
		} else {
			softCache = null;
			
			JarEntry e = getJarEntry(entryName);
			Reader isReader = new InputStreamReader (getInputStream(e));
			StringWriter sw = new StringWriter((int) (e.getCompressedSize()*2));
			
			char[] buffer = new char[8*1024];
			int n = 0;			
			while ((n = isReader.read(buffer)) != -1) {
				sw.write(buffer, 0, n);
			}
			
			str = sw.toString();
			
			this.cache.put(entryName, new SoftReference<Object>(str)); // add it to the cache
		}
				
		return str;
	}
	
	/** Check if all the content of the package is signed. 
	 * @return <tt>true</tt> if every file in the package (apart from those in META-INF/) are signed, <tt>false</tt> otherwise.*/
	public boolean isSigned () {
		return this.allSigned;
	}
	
	/** Check if all the content of the packages is well certified.
	 * @return <tt>true</tt> if all the content of the package is certified with recognized certificates, <tt>false</tt> otherwise. */
	public boolean isCertified () {
		return this.allCertificated;
	}
	/** Check if the package was tampered with (signatures don't match content)
	 * @return <tt>true</tt> if package was tampered with, <tt>false</tt> otherwise.*/
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
