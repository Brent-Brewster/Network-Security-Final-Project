/* This list represents the groups on the server */
import java.util.*;


	public class GroupList implements java.io.Serializable {
		
		/*Serializable so it can be stored in a file for persistence */
		private static final long serialVersionUID = -8911161283900260136L;
		private Hashtable<String, Group> list;
		
		public GroupList()
		{
			list = new Hashtable<String, Group>();
		}
		
		public synchronized void addGroup(String owner, String groupname)
		{
			Group newGroup = new Group(owner);
			list.put(groupname, newGroup);
		}
		
		public synchronized void deleteGroup(String username)
		{
			list.remove(username);
		}
		
		public synchronized boolean checkGroup(String groupname)
		{
			if(list.containsKey(groupname))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		
		public synchronized ArrayList<String> getMembers(String groupname)
		{
			if(list.get(groupname) == null)
			{
				return null;
			}
			return list.get(groupname).getMembers();
		}
		
		public synchronized String getOwner(String groupname)
		{
			return list.get(groupname).getOwner();
		}
		
		public synchronized void addMember(String username, String groupname)
		{
			// if(list.get(groupname) == null)					//Brent Added this in here to check if the group exists well guess what it didn't so I added it in here
			// {
			// 	System.out.println("Group does not exist");
			// 	return;
			// }
			// else
			list.get(groupname).addMember(username);
		}
		
		public synchronized void removeMember(String username, String groupname)
		{
			list.get(groupname).removeMember(username);
		}
		
	
	class Group implements java.io.Serializable {
		
		/**
		 * 
		 */
		private static final long serialVersionUID = 4258398564172781667L;
		private String owner;
		private ArrayList<String> members;
		
		public Group(String owner)
		{
			this.owner = owner;
			members = new ArrayList<String>();
			this.addMember(owner);
		}
		
		public String getOwner()
		{
			return owner;
		}
		
		public ArrayList<String> getMembers()
		{
			return members;
		}
		
		public void addMember(String member)
		{
			members.add(member);
		}
		
		public void removeMember(String member)
		{
			if(!members.isEmpty())
			{
				if(members.contains(member))
				{
					members.remove(members.indexOf(member));
				}
			}
		}
		

	}
	}	
