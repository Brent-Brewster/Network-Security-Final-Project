/* This list represents the shared resources on a host server */

import java.util.*;


	public class ResourceList implements java.io.Serializable {
		
	/*Serializable so it can be stored in a file for persistence */
	private static final long serialVersionUID = -8911161283900260136L;
	private ArrayList<SharedResource> list;
	
	public ResourceList()
	{
		list = new ArrayList<SharedResource>();
	}
	
	public synchronized void addResource(String owner, String group, String id)
	{
		SharedResource newResource = new SharedResource(owner, group, id);
		list.add(newResource);
	}
	
	public synchronized void removeResource(String id)
	{
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i).getID().compareTo(id)==0) {
				list.remove(i);
			}
		}
	}
	
	public synchronized boolean checkResource(String id)
	{
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i).getID().compareTo(id)==0) {
				return true;
			}
		}
		return false;
	}
	
	public synchronized ArrayList<SharedResource> getResources()
	{
		Collections.sort(list);
		return list;			
	}
	
	public synchronized SharedResource getResource(String id)
	{
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i).getID().compareTo(id)==0) {
				return list.get(i);
			}
		}
		return null;
	}
}	
