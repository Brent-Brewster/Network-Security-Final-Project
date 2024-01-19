import java.util.ArrayList;

/* An Envelope is a container for data to be sent over the network. Each envelope
 * has a header message (indicating the purpose of the envelope) and contents. 
 * The contents of an envelope are an array of objects.
 */

public class Envelope implements java.io.Serializable {
	
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private ArrayList<Object> objContents = new ArrayList<Object>();
	
	public Envelope(String text)
	{
		msg = text;
	}
	
	public String getMessage()
	{
		return msg;
	}
	
	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}
	
	public void addObject(Object object)
	{
		objContents.add(object);
	}

}
