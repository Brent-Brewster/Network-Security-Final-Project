import java.util.ArrayList;

import javax.crypto.spec.SecretKeySpec;

public class HostSessionTokenList {
    ArrayList<User> hostSessionTokenList;

    public HostSessionTokenList(){
        hostSessionTokenList = new ArrayList<User>();
    }

    public void addHostSessionToken(String username, SecretKeySpec SessionToken){
        for(User user : hostSessionTokenList)
        {
            if(user.getUserName().equals(username))
            {
                hostSessionTokenList.remove(user);
                break;
            }
        }
        User user = new User(username, SessionToken);
        hostSessionTokenList.add(user);
    }

    public SecretKeySpec getHostSessionToken(String username){
        for(User user : hostSessionTokenList){
            System.out.println("Username passed in: " + username);
            System.out.println(user.getUserName());
            if(user.getUserName().equals(username)){
                System.out.println("Found the user");
                return user.getSessionToken();
            }
        }
        return null;
    }

    private class User{
        String username;
        SecretKeySpec SessionToken;

        public User(String username1, SecretKeySpec SessionToken1){
            username = username1;
            SessionToken = SessionToken1;
        }
        public String getUserName(){
            return username;
        }
        public SecretKeySpec getSessionToken(){
            return SessionToken;
        }
    }
}
