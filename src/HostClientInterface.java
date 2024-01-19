
import java.util.List;

/**
 * Interface describing the operations that must be supported by the
 * client application used to talk with the host servers. 
 */
public interface HostClientInterface
{
    /**
     * Connect to the specified host server.  No other methods should
     * work until the client is connected to a host server.
     *
     * @param server The IP address or hostname of the host server
     * @param port The port that the host server is listening on
     *
     * @return true if the connection succeeds, false otherwise
     *
     */
    public boolean connect(final String server, final int port);


    /**
     * Close down the connection to the host server.
     *
     */
    public void disconnect();


    /**
     * Retrieves a list of resources that are allowed to be displayed
     * by members of the groups encoded in the supplied user token.
     *
     * @param token The UserToken object assigned to the user invoking this operation
     *
     * @return A list of SharedResource objects
     *
     */
    public List<SharedResource> listResources(final UserToken token);


    /**
     * Uploads a resource to the server to be shared with members of the
     * specified group.  This method should only succeed if the
     * uploader is a member of the group that the resource will be shared
     * with.
     *
     * @param localResource The local resource to upload
     * @param remoteResource   The remote resource to be used on the server
     * @param group      The group to share this resource with
     * @param token      The token of the user uploading the resource
     *
     * @return true on success, false on failure
     *
     */
    public boolean upload(final SharedResource localResource, 
                          final SharedResource remoteResource, 
                          final String group, final UserToken token);


    /**
     * Downloads a resource from the server.  The user must be a member of
     * the group with which this resource is shared.
     *
     * @param remoteResource The remote resource on the server
     * @param localResource   The local resource to use locally
     * @param token      The token of the user uploading the resource
     *
     * @return true on success, false on failure
     *
     */
    public boolean download(final SharedResource remoteResource, 
                            final SharedResource localResource, 
                            final UserToken token);


    /**
     * Deletes a resource from the server.  The user must be a member of
     * the group with which this resource is shared.
     *
     * @param resource The resource to delete
     * @param token    The token of the user requesting the delete
     *
     * @return true on success, false on failure
     *
     */
    public boolean delete(final SharedResource resource, final UserToken token);


}  //-- end interface HostClientInterface