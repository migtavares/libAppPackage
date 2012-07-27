
# Certificates

## Example keytore information

	keystore file   : example.keystore
	keystore pasword: keystore
	      alias name: alias
	        password: alias.
	      alias name: saila
	        password: saila.

## Creating the keystore
	keytool -keystore example.keystore -genkey -alias alias
	keytool -keystore example.keystore -genkey -alias saila

## Creating the certificate files

	keytool -keystore example.keystore -alias alias -export -file alias.cert
	keytool -keystore example.keystore -alias saila -export -file saila.cert

# Packages

# Creating a package
	jar -cf package.pak -C package/ .

# Signing a package
	jarsigner -keystore example.keystore -signedjar package.signed.pak package.pak alias

# Tampering with the signed package
Unzip the package, change some digest in the META-INF/MANIFEST.MF file and zip it again.

# Verifying the signature of the package
	jarsigner -verify -certs -verbose -keystore example.keystore package.signed.pak
	jarsigner -verify -certs -verbose -keystore example.keystore package.tampered.pak

The first one should show the contents with a valid signature, described in the manifest and with the certificate found in the keystore.
The later should fail complaining of invalid signatures.