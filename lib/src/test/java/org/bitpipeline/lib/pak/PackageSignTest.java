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

import java.awt.image.BufferedImage;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.imageio.ImageIO;

import junit.framework.TestCase;

import org.junit.Test;

public class PackageSignTest extends TestCase {

	@Test
	public void testSignedWithInvalidCertificate () throws IOException, CertificateException {
		PakFile pak;
		
		FileInputStream fis = new FileInputStream("src/test/resources/saila.cert");
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Certificate sailaCert = cf.generateCertificate(fis);
		
		pak = new PakFile ("src/test/resources/package.signed.pak", sailaCert, true);
		
		assertTrue ("Contents of package should be signed.", pak.isSigned ());
		assertTrue ("Contents of package are certified but with invalid certification.", !pak.isCertified ());
		assertTrue ("Package is not tampered.", !pak.isTampered ());
	}

	@Test
	public void testSignedWithValidCertificate () throws IOException, CertificateException {
		PakFile pak;
		
		FileInputStream fis = new FileInputStream("src/test/resources/alias.cert");
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Certificate sailaCert = cf.generateCertificate(fis);
		
		pak = new PakFile ("src/test/resources/package.signed.pak", sailaCert, true);
		
		assertTrue ("Contents of package are signed but are reported as not signed.", pak.isSigned ());
		assertTrue ("Contents of package are certified with valid certification.", pak.isCertified ());
		assertTrue ("Package is not tampered.", !pak.isTampered ());
	}

	
	
	@Test
	public void testSignedWithAnyCertificate () throws IOException {
		PakFile pak;
		pak = new PakFile ("src/test/resources/package.signed.pak", true);
		
		assertTrue ("Contents of package are signed but are reported as not signed.", pak.isSigned ());
		assertTrue ("Contents of package are certified.", pak.isCertified ());
		assertTrue ("Package is not tampered.", !pak.isTampered ());
	}

	@Test
	public void testUnSignedPackage () throws IOException {
		PakFile pak;
		pak = new PakFile ("src/test/resources/package.pak", new X509Certificate[0], true);
		
		assertTrue ("Contents of package are not signed but are reported to be signed.", !pak.isSigned ());
		assertTrue ("Contents of package are not certified but are reported to have a valid certification.", !pak.isCertified ());
		assertTrue ("There's no way of knowing if the package was tampered.", !pak.isTampered ());
	}

	@Test
	public void testTamperedSignedPackage () throws IOException {
		PakFile pak;
		pak = new PakFile ("src/test/resources/package.tampered.pak", new X509Certificate[0], true);
		
		assertTrue ("Contents of package are signed but are reported not to be signed.", pak.isSigned ());
		assertTrue ("package IS tampered.", pak.isTampered ());
		assertTrue ("Contents of package are not certified but are reported to have a valid certification.", pak.isCertified ());
	}
	
	@Test
	public void testReadingStringFile () throws IOException {
		PakFile pak;
		pak = new PakFile ("src/test/resources/package.signed.pak", true);
		
		String indexStr = pak.getEntryAsString ("index.json");
		assertNotNull ("Content of the index.json should not be null", indexStr);
		assertTrue ("Content of index.json should have length bigger than 0", indexStr.length () > 0);
		
		String indexStr2 = pak.getEntryAsString ("index.json");
		assertNotNull ("Content of the index.json should not be null", indexStr2);
		assertTrue ("Content of index.json should have length bigger than 0", indexStr2.length () > 0);
		
		assertTrue ("Should be the same pointer", indexStr == indexStr2);
	}

	@Test
	public void testReaders () throws IOException {
		PakFile pak = new PakFile ("src/test/resources/package.pak", false);
		
		PakEntryReader<?> imageReader = pak.getEntryAs ("android.png", new PakEntryReader<BufferedImage>() {
			BufferedImage image = null;
			@Override
			public void readEntry (String entryName, InputStream is) throws IOException, SecurityException {
				this.image = ImageIO.read (is);
			}

			@Override
			public boolean setResult (Object result) {
				if (result instanceof BufferedImage)
					return true;
				return false;
			}

			@Override
			public BufferedImage getEntry () {
				return this.image;
			}
		});
		
		BufferedImage img = (BufferedImage) imageReader.getEntry ();
		assertNotNull (img);
		assertTrue ("Image should have 119 px of height", img.getHeight () == 119);
		assertTrue ("Image should have 100 px of width", img.getWidth () == 100);
	}
}
