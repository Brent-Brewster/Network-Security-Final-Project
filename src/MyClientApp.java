
import java.util.Scanner;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

public class MyClientApp{

    private static void promptForInput()
    {
        System.out.println("Enter What the number of the opperation you'd like to preform: \n1. seeGroups\n2. createGroup\n3. deleteGroup\n4. addUser\n5. deleteUser\n6. addUserToGroup\n7. removeUserFromGroup\n8. listSharedFiles\n9. listMembers\n10. delete\n11. upload\n12. download\n13. logout\n");
    }

    private static void testBC()
        throws GeneralSecurityException
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        //System.out.println("Maximum AES Key Size is " + maxKeySize);
    }

    private static void displayGroups(UserToken token)
    {
        List<String> groups;
        groups = token.getGroups();
        System.out.println("Your groups are: ");
        for(String group: groups)
        {
            System.out.print(group + ", " );
        }
        System.out.println("\n");
    }

    private static boolean isAdmin(UserToken token)
    {
        for(String group : token.getGroups())
        {
            if(group.equals("ADMIN"))
            {
                return true;
            }
        }
        return false;
    }
    
    //Since our application creates messaging servers each group is treated as a server
    //therefore whenever a new group is created a new file is also created for that groups messages to be saved in
    //this creation happens here
    private static void addGroup(String groupName, UserToken token, AuthenticationClient auth, HostClient File)
    {

        if(!isAdmin(token))
        {
            System.out.println("Sorry, you need to be an administratior to perform this action :( ");
            return;
        }
        else
        {
            System.out.println("Attempting to create a group with groupname, " + groupName);
            boolean groupcreated = auth.createGroup(groupName, token);

            if(!groupcreated){
                System.out.println("Error creating group");
            }
   
        }
    }
    //will need to delete the file of this group as well have not implemented that 
    private static void deleteGroup(String groupName, UserToken token, AuthenticationClient auth)
    {
        if(!isAdmin(token))
        {
            System.out.println("Sorry, you need to be an administratior to perform this action :( ");
            return;
        }
        else
        {
            System.out.println("Attempting to delete a group with groupname, " + groupName);
            
            if(auth.deleteGroup(groupName, token)){
                System.out.println("Done!");
            }
            else{
                System.out.println("Failed to delete group");
            }
        } 
    }

    private static void addUser(String username, UserToken token, AuthenticationClient auth)
    {
        if(!isAdmin(token))
        {
            System.out.println("Sorry, you need to be an administratior to perform this action :( ");
            return;
        }
        else
        {
            System.out.println("Attempting to add a user with username, " + username);
            if(auth.createUser(username,token)){
                System.out.println("Done!");
            }
            else{
                System.out.println("Failed to add user");
            }
        }
    }
    
    private static void removeUser(String username, UserToken token, AuthenticationClient auth)
    {
        if(!isAdmin(token))
        {
            System.out.println("Sorry, you need to be an administratior to perform this action :( ");
            return;
        }
        else
        {
            System.out.println("Attempting to remove a user with username, " + username);
            
            if(auth.deleteUser(username,token)){
                System.out.println("Done!");
            }
            else{
                System.out.println("Failed to remove user: "+username);
            }
        }
    }

    private static void addUserToGroup(String username, String groupName, UserToken token, AuthenticationClient auth)
    {
        if(!isAdmin(token))
        {
            System.out.println("Sorry, you need to be an administratior to perform this action :( ");
            return;
        }
        else
        {
            System.out.println("Attempting to add a user with username, " + username + " to group, " + groupName);
            if(auth.addUserToGroup(username, groupName, token)){
                System.out.println("Done!");
            }
            else{
                System.out.println("Failed to add user to group");
            }
        }
    }

    private static void removeUserFromGroup(String username, String groupName, UserToken token, AuthenticationClient auth)
    {
        if(!isAdmin(token))
        {
            System.out.println("Sorry, you need to be an administratior to perform this action :( ");
            return;
        }
        else
        {
            System.out.println("Attempting to remove a user with username, " + username + " from group, " + groupName);
            
            if(auth.deleteUserFromGroup(username, groupName, token)){
                System.out.println("Done!");
            }
            else{
                System.out.println("Failed to remove user from group");
            }
        }
    }
    //called when we want to read a groups message file we "download that message file"
    private static SharedResource download(String filename, UserToken sessionToken, HostClient File)
    {
        //get the file from the file server
        //save it to the local directory
        List<SharedResource> recourses = File.listResources(sessionToken);
        for(SharedResource file : recourses)
        {
            if(file.getID().equals(filename))
            {
                System.out.print(file.getID() + ", FOUND ready to read!");
                return file;
            }
        }
        System.out.println("File not found");
        return null;

    }

    //retrive file containing messages from the file server
    //append the input onto that file
    //upload the file back to the file server
    private static void sendMessage(String input, String groupName, UserToken token, HostClient File)
    {
        SharedResource rec = download(groupName + ".txt", token, File);
        if(rec == null)
        {
            System.out.println("File not found");
            return;
        }
        try{
        File file = new File(groupName + ".txt");
        FileWriter fr = new FileWriter(file, true);
        fr.append(input);
        fr.close();
        File.upload(rec, rec, groupName, token);   
        }
        catch(IOException e)
        {
            System.out.println("Error writing to file");
        }
    }
    private static UserToken getSessionToken(String username, AuthenticationClient Auth)
    {
        return Auth.getToken(username);
    }
    private static boolean verifyPkcs1Signature(PublicKey rsaPublic, byte[] input, byte[] encSignature) throws Exception {
		Signature signature = Signature.getInstance("SHA384withRSA", "BC");
		signature.initVerify(rsaPublic);
		signature.update(input);
		return signature.verify(encSignature);
	} 

    private static boolean initDiffieHellmanWithHoseServer(HostClient File, String username)
    throws Exception 
    {
        System.out.println("Performing Diffie Hellman Key Exchange with Host Server for user: " + username + "...");
        if(File.performDHWithHostServer(username))
        {
            System.out.println("Diffie Hellman Key Exchange Successful");
            return true;
        }
        else
        {
            System.out.println("Diffie Hellman Key Exchange Failed");
            return false;
        }
        
    }

    public static String solvePuzzle(String message, int hardness) {
        String puzzle = "";
        try {
            // use SHA-256 hash function
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // nonce number to be appended to the message
            int x = 3;
            // Build the puzzle string and check if the hash has the required number of leading zeros yet
            while (true) {
                // This temp string will make up our data to get hashed
                String temp = message + x;
                // Compute hash
                byte[] hash = md.digest(temp.getBytes("UTF-8"));
                // While our condition is not met this will keep going until we find a solution
                if (checkLeadingZeros(hash, hardness)) {
                    puzzle = temp;
                    break;
                }
                // Continue iteration 
                x++;
            }
        } catch (Exception e) {
            System.out.println("Error solving puzzle");
        }
        return puzzle;
    }
    // Helper Method
    public static boolean checkLeadingZeros(byte[] hash, int hardness) {
        // Iterate through our hash digest to check our leading zeros
        for (int i = 0; i < hardness; i++) {
            if (hash[i] != 0) {
                return false;
            }
        }
        // Shift and mask remaining bits since inital check failed
        int checkRemaining = hardness % 8;
        if (checkRemaining != 0) {
            int shift = 8 - checkRemaining;
            // Get relevant bits to check
            int mask = 0xFF << shift;
            // apply the mask and check result
            if ((hash[hardness / 8] & mask) != 0) {
                return false;
            }
        }
        // Everything passed we have the required number of leading zeros
        return true;
    }

    

    private static void sendAuthsPKtoHostServer(HostClient File)
    {
        File.sendAuthsPKtoHostServer();
    }

    public static void main(String argd[])
    throws Exception
    {
            testBC();
            int asport;
            int hsport;
            Scanner scan = new Scanner(System.in);
            String host = "";
            String Authentication = "";
            System.out.println("Welcome to the Group File Sharing Application");
            System.out.println("Enter the IP of the Authentication Server if it is your own device enter localHost: ");
            Authentication = scan.nextLine();
            while(true)
            {
                System.out.println("Enter the port number of the Authentication Server: ");
                try{
                    asport = scan.nextInt();
                    scan.nextLine();
                    break;
                }
                catch(Exception e)
                {
                    System.out.println("Invalid port number");
                    scan.nextLine();
                }
            }
            AuthenticationClient Auth = new AuthenticationClient();
            if(Auth.connect(Authentication, asport))                     
            {
                
                System.out.println("Connected to the Authentication Server");
            }
            else
            {
                System.out.println("Failed Connection to Authentication server");//did not connect do somthing here maybe
            }
            System.out.println("Enter the IP of the File Server if it is your own device enter localHost: ");
            host = scan.nextLine();
            while(true)
   		    {
        	System.out.println("Enter the port number of the Host Server: ");
			try{
				hsport = scan.nextInt();
				scan.nextLine();
				break;
			}
			catch(Exception e)
			{
				System.out.println("Invalid port number");
				scan.nextLine();
			}
		    }
            HostClient File = new HostClient();
            if(File.connect(host, hsport))
            {
                PublicKey publicKey = File.getPublicKey();
				try
				{
					FileInputStream fis = new FileInputStream("HostPublicKey.bin");
					ObjectInputStream fileStream = new ObjectInputStream(fis);
				}
				catch(FileNotFoundException e)
				{
					System.out.println("HostPublicKey file does not exist creating one");
					try
					{
						ObjectOutputStream outStream; 
						outStream = new ObjectOutputStream(new FileOutputStream("HostPublicKey.bin"));
						outStream.writeObject(publicKey);
                        outStream.close();
					}
					catch(Exception c)
					{
						System.err.println("Error: " + c.getMessage());
						c.printStackTrace(System.err);
					}
				}
                // Generate Challenge
                SecureRandom random = new SecureRandom();
                byte[] challenge = new byte[32];
                random.nextBytes(challenge);
                
                // Encrypt Challenge using the host public key
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                byte[] encryptedChallenge = cipher.doFinal(challenge);

                // Send encrypted challenge back to the host server
                byte[] signedResponse = File.getChallenge(encryptedChallenge);
                if(verifyPkcs1Signature(publicKey, challenge, signedResponse)){
                    System.out.println("Challenge Successful, Host Server Verified");
                    System.out.println("Connected to the HOST Server");
                }
                else{
                    System.out.println("Challenge Failed, Bad host Server Detected.");
                    File.disconnect();
                }
                
            }
            else
            {
                System.out.println("Failed Connection to HOST server");
            }
            //establish a connection with the authentication server
            // get the username of the user 
            String username = "";
            System.out.println("Please enter your Username: ");
            String input = "";
            username = scan.nextLine();
            System.out.println("You input: " + username);
            UserToken sessionToken;
            sessionToken = getSessionToken(username, Auth);
            Auth.getSessionTokenWithAS(username);
            if(sessionToken == null)
            {
                System.out.print("Invalid user");
                while(sessionToken == null)
                {
                    System.out.println("Please enter your Username: ");
                    username = scan.nextLine();
                    System.out.println("You input: " + username);
                    sessionToken = getSessionToken(username, Auth);
                }
            }
            if(sessionToken != null)
            {
                initDiffieHellmanWithHoseServer(File, username);
                sendAuthsPKtoHostServer(File); 
                System.out.println("Valid Username");
                System.out.println("Welcome, " + input);
            //use that username to get the user token from the suthentications server
            while(!input.toUpperCase().equals("EXIT"))
            {
                
                promptForInput();
                input = scan.nextLine();

                if(!sessionToken.isTokenValid()) {
                    System.out.println("Sorry, your token is expired, please reconnect");
                    input = "EXIT";
                    
                }
                if(sessionToken.isTokenValid()) {
                    System.out.println("TOKEN STILL VALID, ISTOKENVALID == TRUE BUD");
                }
                //Example of message and hardness
                String message = "If you solve this and we verify it has 'x' leading zeros you can come";
                int hardness = 5;

                String solution = solvePuzzle(message, hardness);
                boolean result = Auth.verifyPuzzle(message, hardness, solution);
                System.out.print(result+": Puzzle Verified, proceeding to menu");
                
                //Get the clients response to the puzzle and verify it
                switch(input)
                {
                case "1": //seeGroups
                    displayGroups(sessionToken);
                break;
                case "2"://createGroup
                    System.out.println("Enter new Group Name: ");

                    input = scan.nextLine();
                    addGroup(input, sessionToken, Auth, File);
                    sessionToken = getSessionToken(username, Auth);
                break;
                case "3"://DELETEGROUP
                    System.out.println("Enter the name of the group you would like do delete: ");
                    input = scan.nextLine();
                    deleteGroup(input, sessionToken, Auth);
                    sessionToken = getSessionToken(username, Auth);
                break;
                case "4"://addUser
                    System.out.println("Enter the name of the user you would like to add: ");
                    input = scan.nextLine();
                    addUser(input, sessionToken, Auth);
                    sessionToken = getSessionToken(username, Auth);
                break;
                case "5"://deleteUser
                    System.out.println("Enter the name of the user you would like to delete: ");
                    input = scan.nextLine();
                    removeUser(input, sessionToken, Auth);
                    sessionToken = getSessionToken(username, Auth);
                break; 
                case "6"://addUserToGroup
                    System.out.println("Enter the name of the group you'd like to add the user too: ");
                    String groupName = scan.nextLine();
                    System.out.println("Enter the name of the user you'd like to add to the group " + groupName + ": ");
                    input = scan.nextLine();
                    addUserToGroup(input, groupName, sessionToken, Auth);
                    sessionToken = getSessionToken(username, Auth);
                break;
                case "7"://removeUserFromGroup
                    System.out.println("Enter the name of the group you'd like to remove the user from: ");
                    groupName = scan.nextLine();
                    System.out.println("Enter the name of the user you'd like to remove from the group " + groupName + ": ");
                    input = scan.nextLine();
                    removeUserFromGroup(input, groupName, sessionToken,Auth);
                break;
                case "8"://listSharedFiles
                    List<SharedResource> sharedFiles = File.listResources(sessionToken);
                    if(sharedFiles == null){
                        System.out.println("No Shared Resources are available\n");
                    }
                    else{
                        for(int i = 0; i < sharedFiles.size() ; i++)
                        {
                            SharedResource file = sharedFiles.get(i);
                            System.out.println(file.getID());
                        }
                    }
                break;
                case "9"://listMembers
                    sessionToken = getSessionToken(username, Auth);
                    System.out.println("Enter the name of the Group whose members you'd like to see: ");
                    input = scan.nextLine();
                    List<String> members = Auth.listMembers(input, sessionToken);
                    if(members != null && members.size() != 0){
                        for(String member : members){
                            System.out.println(member);
                        }
                    }
                    else{
                        if(members == null){
                        System.out.println("No group with groupname: " + input);
                        }
                        else{
                        System.out.println("No members in group: " + input);
                        }
                    }
                break;
                case "read"://read
                    System.out.println("Enter the name of the Group you'd like to read: ");
                    input = scan.nextLine();
                    download(input, sessionToken, File);
                break;
                case "send":
                    System.out.println("Enter the Name of the Group you'd like to message: ");
                    groupName  = scan.nextLine();
                    System.out.println("Enter the Message you'd like to send to group " + groupName + ": ");
                    input = scan.nextLine();
                    sendMessage(input, groupName, sessionToken, File);
                break;
                case "connectToNewFileServer":
                    File.disconnect();
                    System.out.println("Enter the IP of the File Server if it is your own device enter localHost: ");
                    host = scan.nextLine();
                 
                    if(File.connect(host, hsport))
                    {
                        // Host server sends public key to client 
                        
                        System.out.println("Connected to the HOST Server");
                    }
                    else
                    {
                        System.out.println("Failed Connection to HOST server");
                    }
                    break;
                case "13"://logout
                    sessionToken = null;
                    System.out.println("Please enter your Username: ");
                    username = scan.nextLine();
                    System.out.println("You input: " + username);
                    sessionToken = getSessionToken(username, Auth);
                    while(sessionToken == null)
                    {
                        System.out.println("Invalid username");
                        System.out.println("Please enter your Username: ");
                        username = scan.nextLine();
                        System.out.println("You input: " + username);
                        sessionToken = Auth.getToken(username);
                    }
                    break;
                case "11"://upload
                    System.out.println("Enter the name of the file you'd like to upload: ");
                    input = scan.nextLine();
                    System.out.println("Enter the name of the group you'd like to upload the file to: ");
                    groupName = scan.nextLine();
                    SharedResource rec = new SharedResource(sessionToken.getSubject(), groupName, input);
                    File.upload(rec, rec, groupName, sessionToken);
                    break;
                case "12"://download
                    System.out.println("Enter the name of the file you'd like to download: ");
                    input = scan.nextLine();
                    SharedResource rec2 = new SharedResource(sessionToken.getSubject(), sessionToken.getSubject(), input);
                    File.download(rec2, rec2, sessionToken);
                    break;
                case "10"://delete
                    System.out.println("Enter the name of the file you'd like to delete: ");
                    input = scan.nextLine();
                    SharedResource rec3 = new SharedResource(sessionToken.getSubject(), sessionToken.getSubject(), input);
                    File.delete(rec3, sessionToken);
                    break;
                }//end of switch 
                
            }//end of while loop
            }//end of else statement
            System.out.println("Goodbye : )");

             
    }

}