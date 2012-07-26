package org.bitpipeline.lib.pak;

import java.io.IOException;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.junit.Test;

public class PackageSignTest extends TestCase {

	@Test
	public void testSignedWithInvalidCertificate () throws IOException {
		PakFile pak;
		pak = new PakFile ("src/test/resources/package.signed.pak", new X509Certificate[0], true);
		
		assertTrue ("Contents of package are signed but are reported as not signed.", pak.isSigned ());
		assertTrue ("Contents of package are certified but with invalid certification.", !pak.isCertified ());
		assertTrue ("Package is not tampered.", !pak.isTampered ());
	}

	@Test
	public void testSignedWithAnyCertificate () throws IOException {
		PakFile pak;
		pak = new PakFile ("src/test/resources/package.signed.pak", null, true);
		
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
		pak = new PakFile ("src/test/resources/package.signed.pak", null, true);
		
		String indexStr = pak.getEntryAsString ("index.json");
		assertNotNull ("Content of the index.json should not be null", indexStr);
		assertTrue ("Content of index.json should have length bigger than 0", indexStr.length () > 0);
	}

}
