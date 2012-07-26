package android.graphics.drawable;

import java.io.InputStream;

public class Drawable {
	final String name;
	
	public Drawable(String name) {
		this.name = name;
	}
	
	public static Drawable createFromStream(InputStream is, String srcName) {
		return new Drawable (srcName);
	}
}
