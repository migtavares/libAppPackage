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

/** Interface used to create specific entry reader for pak files.
 * For example to read images or specific object classes. */
public interface PakEntryReader<T> {
	/** Perform the reading and instantiation to a object of a pak entry.
	 * @param entryName is the name of the entry to be read.
	 * @param is is the input stream for the pak entry with the name provided in entryName
	 * @throws IOException if there is a error reading the entry
	 * @throws SecurityException if there is a problem with the signature of the entry. */
	void readEntry (String entryName, InputStream is) throws IOException, SecurityException;
	
	/** Used to set the result from cache.
	 * @return <tt>true</tt> if the result object is of the expected type, <tt>false</tt> otherwise. */
	boolean setResult (Object result);
	
	/** Get's the entry as a intance of a object.
	 * @return the instance of the object as readed from the entry. */
	T getEntry ();
}