
import java.util.List;

/**
 * A simple interface to the token data structure that will be
 * returned by a group server.  
 *
 * You will need to develop a class that implements this interface so
 * that your code can interface with the tokens created by your group
 * server.
 *
 */
public interface UserToken
{
    /**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Alice" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public String getIssuer();


    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject();


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups();


    /** 
    * This method adds a group to a user's token given that it is not already present, 
    * and return a bool indicating if the operation was successful. If "Alice" is a 
    * member of group "G1" but not "G2", then this method would return True if passed "G2",
    * and False is passed "G1"
    *
    * @return boolean indicating whether the operation was a success 
    *
    * Brett - Added to be able to access addGroup() Token method, since Token class is only used
    * to instantiate UserToken objects, and it would be otherwise impossible to add 
    * groups to a userToken which is a necessary function
    */
    public boolean addGroup(String _group);

    /** 
    * This method adds a signature to a token
    *
    * @return boolean indicating whether the operation was a success 
    *
    * Brett - Added as a helper function to be implement T2 of phase 3. Allows tokens to be signed
    * by the authentication server's private key for later checking by host servers or users.
    */
    public boolean signToken(byte[] _signature);


    /** 
    * This returns the authentication server's signature attached to any users given token
    *
    * @return the signature string stored inside a token
    *
    * Brett - Added as a helper function to be implement T2 of phase 3. Allows token signatures to be obtained by the host server
    */
    public byte[] getSignature();

    public byte[] getBytes();

    public boolean isTokenValid();

    
}   //-- end interface UserToken
