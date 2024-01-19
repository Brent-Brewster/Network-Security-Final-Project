import java.security.PublicKey;
import java.util.*;


	public class AuthenticationServerUserKeys implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 7600343803563417992L;
		private Hashtable<String, User> list = new Hashtable<String, User>();
		
		public synchronized void addUser(String username)
		{
			User newUser = new User();
			list.put(username, newUser);
		}

		//retrive a user from the user lise
		public synchronized User getUser(String username)
		{
			return list.get(username);
		}
		
		public synchronized void deleteUser(String username)
		{
			list.remove(username);
		}
		
		public synchronized boolean checkUser(String username)
		{
			if(list.containsKey(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
        public synchronized void setPublicKey(String username, PublicKey key)
        {
            User user = list.get(username);
            user.setPublicKey(key);
        }
        public synchronized PublicKey getPublicKey(String username)
        {
            User user = list.get(username);
            return user.getPublicKey();
        }
	class User implements java.io.Serializable {
		/**
		 * 
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		PublicKey publickey;
		
		public User()
		{
			publickey = null;
		}

		public PublicKey getPublicKey()
		{
			return publickey;
		}

		public void setPublicKey(PublicKey key)
		{
			publickey = key;
		}

		
	}
	
}	

