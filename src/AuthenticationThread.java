/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.math.BigInteger;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
/*Import necessary packages for security/bouncycastle */
import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.directory.NoSuchAttributeException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

public class AuthenticationThread extends Thread 
{
	private final Socket socket;
	private AuthenticationServer my_gs;
	
	public AuthenticationThread(Socket _socket, AuthenticationServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}
	
	public void run()
	{
		boolean proceed = true;
		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			//Instantiate BC as the security provider
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			KeyPair ASRSAKeyPair;
			ObjectInputStream fileStream;
				try
				{
					FileInputStream fis = new FileInputStream("NotASRSAKey.bin");
					fileStream = new ObjectInputStream(fis);
					ASRSAKeyPair = (KeyPair)fileStream.readObject();
				}
				catch(FileNotFoundException e)
				{
					System.out.println("ASKEY does not exist creating one");
					ASRSAKeyPair = generateRSAKeyPair(); 
					try
					{
						ObjectOutputStream outStream; 
						outStream = new ObjectOutputStream(new FileOutputStream("NotASRSAKey.bin"));
						outStream.writeObject(ASRSAKeyPair);
					}
					catch(Exception c)
					{
						System.err.println("Error: " + c.getMessage());
						c.printStackTrace(System.err);
					}
				}
			
			/*TODO: add logic to read in keys from file? no wdym to do it's done it's up there ^^^^ Look at it */
			

			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;
				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					byte[] signedUserName = (byte[])message.getObjContents().get(1);//get signiture of client 
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						//the first step in the T1 protocol is to chek if the user has logged in before all new
						//users have their publicKey field set to NONE by default if it's none they have been created
						//by the admin but not yet logged into their own cient 
						
						if(my_gs.userList.checkUser(username) && my_gs.userList.getUser(username).getPublicKey() == null)
						{
							System.out.println("No Public key found! User has not logged in before");
							//no public key has been found we need to perform a DHKE generate the prime and base p and g
							System.out.println("Generating prime and base");
							DHParameterSpec primeAndBase = generateParameters();
							//send the prime and base to the client
							response = new Envelope("DHKEP");
							response.addObject(primeAndBase.getP());//pack up that prime mod
							response.addObject(primeAndBase.getG());//pack up that gen number
							System.out.println("Sending Prime and base to the client");
							output.writeObject(response);
						}
						else
						{
						if(my_gs.userList.checkUser(username) && signedUserName != null && verifyPkcs1Signature(my_gs.userList.getUser(username).getPublicKey(), username.getBytes(), signedUserName))
						{
						System.out.println("Creating user token");
						UserToken yourToken = createToken(username); //Create a token
						//Respond to the client. On error, the client will receive a null token
						PublicKey aspub = null;
						try
						{
							ObjectInputStream ois = new ObjectInputStream(new FileInputStream("NotASRSAKey.bin"));
							ASRSAKeyPair = (KeyPair)ois.readObject();
							aspub = ASRSAKeyPair.getPublic();
						}
						catch(Exception e)
						{
							System.out.println("Error reading in ASRSAKeyPair");
						}
						//start a dhke with the user to generate a shared secretethat will act as the session token

						response = new Envelope("OK");
						response.addObject(yourToken);
						response.addObject(aspub);
						System.out.println("Sending User token");
						output.writeObject(response);
						System.out.println("Response sent!");
						}
						else
						{
							response = new Envelope("FAIL");
							response.addObject(null);
							output.writeObject(response);
							//user gets null token when not verified by the AS
						}
						}
				}
			}
				//DH public key recived from client 
				//compute the shared secrete with this
				//This was really boring to write
				else if(message.getMessage().equals("DHKPK"))
				{
					System.out.println("DH public key recived from Client");
					BigInteger p = (BigInteger)message.getObjContents().get(1); //prime mod val
					BigInteger g = (BigInteger)message.getObjContents().get(2); //generator value
					//DHParameterSpec PandG = new DHParameterSpec(p, g);
					//KeyP ASKeyPair = generateDHKeyPair(PandG);
					//now that we have the clients public key and the servers private key we can generate the shared secrete s
					//byte[] sharedSecrete = initiatorAgreement(ASKeyPair.getPrivate(), (PublicKey)message.getObjContents().get(0));
					//now that we have the shared secrate we can generate the clients RSA key pair and send it to them encrypted by the ss
					//SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecrete, "AES");
					Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
					//cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
					response = new Envelope("PAIR");
					response.addObject(ASRSAKeyPair.getPublic());
					String username = (String)message.getObjContents().get(3);
					PublicKey useresPublicKey = (PublicKey)message.getObjContents().get(4);
					my_gs.userList.getUser(username).setPublicKey(useresPublicKey);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 2 || my_gs.userList.checkUser((String)message.getObjContents().get(0)))
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								
								byte[] encryptedToken = (byte[])message.getObjContents().get(1);
								String username = (String)message.getObjContents().get(0); //Extract the username
								String callerUsername = (String)message.getObjContents().get(2);
								
								byte[] decryptedToken = decrypt(encryptedToken, my_gs.userList.getUser(callerUsername).getSessionKey());
								ByteArrayInputStream in = new ByteArrayInputStream(decryptedToken);
								ObjectInputStream out = new ObjectInputStream(in);
								UserToken yourToken = (UserToken)out.readObject();//Extract token
								
								
								if(createUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
				}

				else if(message.getMessage().equals("getSessionTokenWithAS"))
				{
					BigInteger p = new BigInteger(decryptWithRSA((byte[])message.getObjContents().get(0), my_gs.userList.getUser((String)message.getObjContents().get(2)).getPublicKey())); //prime mod val this value is encrypted with the clients key
					BigInteger g = new BigInteger(decryptWithRSA((byte[])message.getObjContents().get(1), my_gs.userList.getUser((String)message.getObjContents().get(2)).getPublicKey())); //generator value this value is encrypted with the clients key
					
					//ByteArrayInputStream in = new ByteArrayInputStream(decryptedP);
					//ObjectInputStream out = new ObjectInputStream(in);
					//BigInteger p = (BigInteger)out.readObject();
					
					//in = new ByteArrayInputStream(decryptedG);
					//out = new ObjectInputStream(in);
					//BigInteger g = (BigInteger)out.readObject();
					int l = (int)message.getObjContents().get(4);
					System.out.println("Value of L: " + l);
					System.out.println("Parameters for DHKE: " + p.toString() + " 		" + g.toString());
					DHParameterSpec PandG = new DHParameterSpec(p, g, 1024);
					KeyPair ASKeyPair = generateDHKeyPair(PandG);
					//now that we have the clients public key and the servers private key we can generate the shared secrete s
					byte[] sharedSecrete = initiatorAgreement(ASKeyPair.getPrivate(), (PublicKey)message.getObjContents().get(3));					//store the session token with the useres name to be used for encrypting and decrypting the messages between client and server
					System.out.println("Servers shared secrete byte []: " + Arrays.toString(sharedSecrete));
					SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecrete, "AES");
					System.out.println("Username being used to store the session key: " + (String)message.getObjContents().get(2) + " Session key: " + secretKeySpec.toString());
					my_gs.userList.getUser((String)message.getObjContents().get(2)).serSessionKey(secretKeySpec);//change user 
					response = new Envelope("ACPAGSIGNED");
					response.addObject(generatePkcs1Signature(ASRSAKeyPair.getPrivate(), PandG.getP().toByteArray()));
					response.addObject(generatePkcs1Signature(ASRSAKeyPair.getPrivate(), PandG.getG().toByteArray()));
					response.addObject(ASKeyPair.getPublic());	//sign this instead
					System.out.println("ASDHPublicKey: " + ASKeyPair.getPublic().toString());
					output.writeObject(response);
					System.out.println("ACPAGSIGNED sent");
				}

				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					if(!my_gs.userList.checkUser((String)message.getObjContents().get(0)))
					{
						response = new Envelope("FAIL");
					}
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								byte[] encryptedToken = (byte[])message.getObjContents().get(1);
								String caller  = (String)message.getObjContents().get(2);
								byte[] decryptedToken = decrypt(encryptedToken, my_gs.userList.getUser(caller).getSessionKey());
								ByteArrayInputStream in = new ByteArrayInputStream(decryptedToken);
								ObjectInputStream out = new ObjectInputStream(in);
								UserToken yourToken = (UserToken)out.readObject();//Extract token
								
								if(my_gs.userList.checkUser((String)message.getObjContents().get(0))){
									if(my_gs.groupList.getMembers("ADMIN").contains(username) && my_gs.groupList.getMembers("ADMIN").size() == 1)
									{
										System.out.println("CANNOT DELETE THE LAST ADMIN!");
										response = new Envelope("FAIL");
									}
									else{
									
										if(deleteUser(username, yourToken))
										response = new Envelope("OK"); //Success
									}			
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				// else if(message.getMessage().equals("PUZZLE")) 
				// {
				// 	if(message.getObjContents().size() < 3) 
				// 	{
				// 		response = new Envelope("FAIL");
				// 	}
				// 	else
				// 	{
				// 		response = new Envelope("FAIL");
						
				// 		if(message.getObjContents().get(0)!= null) {
				// 			if(message.getObjContents().get(1) != null && message.getObjContents().get(2) != null) {
				// 				try {
				// 					MessageDigest md = MessageDigest.getInstance("SHA-256");
				// 					String puzzleMessage = (String)message.getObjContents().get(0);
				// 					String hardness = (String)message.getObjContents().get(1);
				// 					String solution = (String)message.getObjContents().get(2);
									
				// 					String data = puzzleMessage + solution;
				// 					byte[] hash = md.digest(data.getBytes("UTF-8"));
				// 					if(checkLeadingZeros(hash, Integer.parseInt(hardness))) {
				// 						response = new Envelope("OK");
				
				// 					}
				// 				} catch (Exception e) {
				// 					System.out.println("Error in PUZZLE");
				// 					response = new Envelope("Failed to verify puzzle");
				// 				}
				// 			}
				// 		}
				// 	}
				// }
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
				    if(message.getObjContents().size() < 2) 
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null) {
							if(message.getObjContents().get(1) != null) {
								byte[] encryptedGroup= (byte[])message.getObjContents().get(0);
								String username = (String)message.getObjContents().get(2); //Extract the username
								byte[] encryptedToken = (byte[])message.getObjContents().get(1);

								byte[] decryptedToken = decrypt(encryptedToken, my_gs.userList.getUser(username).getSessionKey());
								ByteArrayInputStream in = new ByteArrayInputStream(decryptedToken);
								ObjectInputStream out = new ObjectInputStream(in);
								UserToken yourToken = (UserToken)out.readObject();//Extract token

								String groupname = new String(decrypt(encryptedGroup, my_gs.userList.getUser(username).getSessionKey()));
								
								//String groupname = (String)out.readObject();//Extract token

								if(createGroup(groupname, yourToken)) {
									response = new Envelope("OK"); // Success
								}
							}
						}	
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
				    if(message.getObjContents().size() < 2) 
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null) {
							if(message.getObjContents().get(1) != null) {
								byte[] encryptedGroup= (byte[])message.getObjContents().get(0);
								String username = (String)message.getObjContents().get(2); //Extract the username
								byte[] encryptedToken = (byte[])message.getObjContents().get(1);

								byte[] decryptedToken = decrypt(encryptedToken, my_gs.userList.getUser(username).getSessionKey());
								ByteArrayInputStream in = new ByteArrayInputStream(decryptedToken);
								ObjectInputStream out = new ObjectInputStream(in);
								UserToken yourToken = (UserToken)out.readObject();//Extract token

								String groupname = new String(decrypt(encryptedGroup, my_gs.userList.getUser(username).getSessionKey()));
								
								if(my_gs.groupList.checkGroup(groupname)){
									if(deleteGroup(groupname, yourToken)) {
										response = new Envelope("OK"); // Success
									}
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size() < 2) 
					{
						response = new Envelope("FAIL");
					}
					else 
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null) {
							if(message.getObjContents().get(1) != null) {
								byte[] encryptedGroup= (byte[])message.getObjContents().get(0);
								String username = (String)message.getObjContents().get(2); //Extract the username
								byte[] encryptedToken = (byte[])message.getObjContents().get(1);

								byte[] decryptedToken = decrypt(encryptedToken, my_gs.userList.getUser(username).getSessionKey());
								ByteArrayInputStream in = new ByteArrayInputStream(decryptedToken);
								ObjectInputStream out = new ObjectInputStream(in);
								UserToken yourToken = (UserToken)out.readObject();//Extract token

								String groupname = new String(decrypt(encryptedGroup, my_gs.userList.getUser(username).getSessionKey()));
							
								List<String> members = listMembers(groupname, yourToken);
								response = new Envelope("OK");
								System.out.println("Members after the call: " + members);
								response.addObject(members);
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size() < 2) 
					{
						System.out.println("size incorrect");
						response = new Envelope("FAIL");
					}
					else 
					{
						System.out.println("size correct");
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null) {
							if(message.getObjContents().get(1) != null) {
								byte[] encryptedGroup= (byte[])message.getObjContents().get(1);
								String username = (String)message.getObjContents().get(0); //Extract the username
								byte[] encryptedToken = (byte[])message.getObjContents().get(2);
								String callerUsername = (String)message.getObjContents().get(3);
								byte[] decryptedToken = decrypt(encryptedToken, my_gs.userList.getUser(callerUsername).getSessionKey());
								ByteArrayInputStream in = new ByteArrayInputStream(decryptedToken);
								ObjectInputStream out = new ObjectInputStream(in);
								UserToken yourToken = (UserToken)out.readObject();//Extract token

								String groupname = new String (decrypt(encryptedGroup, my_gs.userList.getUser(callerUsername).getSessionKey()));
								
								if(my_gs.userList.checkUser(username) && my_gs.groupList.checkGroup(groupname) && !my_gs.groupList.getMembers(groupname).contains(username)){
									if(username == null || groupname == null || yourToken == null) {
										System.out.println("username, groupname, or token is null \n Adding user to group failed");
									}
									if(addUserToGroup(username, groupname, yourToken)) {
										response = new Envelope("OK"); // Success
									}
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
				    
					if(message.getObjContents().size() < 2) 
					{
						response = new Envelope("FAIL");
					}
					else 
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null) {
							if(message.getObjContents().get(1) != null) {
								byte[] encryptedGroup= (byte[])message.getObjContents().get(1);
								String username = (String)message.getObjContents().get(0); //Extract the username
								byte[] encryptedToken = (byte[])message.getObjContents().get(2);
								String caller = (String)message.getObjContents().get(3);
								byte[] decryptedToken = decrypt(encryptedToken, my_gs.userList.getUser(caller).getSessionKey());
								ByteArrayInputStream in = new ByteArrayInputStream(decryptedToken);
								ObjectInputStream out = new ObjectInputStream(in);
								UserToken yourToken = (UserToken)out.readObject();//Extract token

								String groupname = new String(decrypt(encryptedGroup, my_gs.userList.getUser(caller).getSessionKey()));

								System.out.println("UserName: " + username + " GroupName: " + groupname + " Token: " + yourToken);
								if(my_gs.userList.checkUser(username) && my_gs.groupList.checkGroup(groupname) && my_gs.groupList.getMembers(groupname).contains(username))
								if(deleteUserFromGroup(username, groupname, yourToken)) {
									response = new Envelope("OK"); // Success
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					output.writeObject(response);
				}
			}while(proceed);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	private static DHParameterSpec generateParameters()
		throws GeneralSecurityException
	{
		AlgorithmParameterGenerator algGen = AlgorithmParameterGenerator.getInstance("DH", "BC");
 		algGen.init(1024);
		System.out.println("Generating inside the generate method");
 		AlgorithmParameters dsaParams = algGen.generateParameters();
		System.out.println("Done with generation returning");
		return dsaParams.getParameterSpec(DHParameterSpec.class);
	}
	//Method to create tokens
	private UserToken createToken(String username)
		throws Exception 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			KeyPair ASRSAKeyPair = null;
			ObjectInputStream fileStream;
				try
				{
					FileInputStream fis = new FileInputStream("NotASRSAKey.bin");
					fileStream = new ObjectInputStream(fis);
					ASRSAKeyPair = (KeyPair)fileStream.readObject();
				}
				catch(FileNotFoundException e)
				{
					System.out.println("ASKEY does not exist!"); 
				}
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
			
			//Sign the token with the authentication servers private key to ensure it isn't forged or modified
			byte[] tokenData = (yourToken.getIssuer()+yourToken.getSubject()+yourToken.getGroups()).getBytes(); 
			byte[] signature = generatePkcs1Signature(ASRSAKeyPair.getPrivate(), tokenData);
			
			yourToken.signToken(signature);
			

			return yourToken;
		}
		else
		{
			return null;
		}
	}
	
	
	//Method to delete a group
	private boolean deleteGroup(String groupname, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			//Is the requester an owner?
			if(my_gs.userList.getUserOwnership(requester).contains(groupname))
			{
				
				//Get membership list from the group list
				List<String> deleteFromUsers = my_gs.groupList.getMembers(groupname);
				
				//Go into each user and delete the reference to the group
				for(int index = 0; index < deleteFromUsers.size(); index++)
				{
					my_gs.userList.removeGroup(deleteFromUsers.get(index), groupname);
				}
				
				//Remove requester's ownership of this group
				my_gs.userList.removeOwnership(requester, groupname);
				
				//Remove group from the group list
				my_gs.groupList.deleteGroup(groupname);
				
				return true;
			}
			else
			{
			
				return false; //Requester not an owner
				
			}
		}		
		else
		{
			
			return false; //Requester does not exist
		}
	}

			//method to gereate and return a DHKP using the p and g 
			private static KeyPair generateDHKeyPair(DHParameterSpec PandG)
			throws GeneralSecurityException
			{
				KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DH", "BC");
			 	keyPair.initialize(PandG);
			 	return keyPair.generateKeyPair();
			}
			public static byte[] initiatorAgreement(PrivateKey initiatorPrivate, PublicKey recipientPublic)
 				throws GeneralSecurityException
			{
 				KeyAgreement agreement = KeyAgreement.getInstance("DH", "BC");
 				agreement.init(initiatorPrivate);
 				agreement.doPhase(recipientPublic, true);
 				SecretKey agreedKey = agreement.generateSecret("AES[256]");
 				return agreedKey.getEncoded();
			} 

	// Method to create a group
	private boolean createGroup(String groupname, UserToken yourToken) 
	{
		// Get the requester's name from the token
		String requester = yourToken.getSubject();
		// Check if requester exists
		if(my_gs.userList.checkUser(requester)) 
		{
			// Does requester already own this group?
			if(!my_gs.userList.getUserOwnership(requester).contains(groupname)) 
			{
				// Create the group, needs two arguments
				// GroupName and OwnerName
				my_gs.userList.addGroup(requester, groupname);
				my_gs.userList.addOwnership(requester, groupname);
				my_gs.groupList.addGroup(requester, groupname);//we were missing this never actually maing the group

				//my_gs.userList.addGroup(groupname, requester);

				// Add requester as owner of this group
				//my_gs.userList.addOwnership(requester, groupname);
				//System.out.println("returning true");
				return true;
			}
			else 
			{
				//System.out.println("logic error false 1?");
				return false; // Requester already owns this group
			}
		} else {
			return false; //requester does not exist
		}
	}
	
	//Method to create a user
	private boolean createUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();
					
					//This will produce a hard copy of the list of groups this user belongs
					
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}
					
					for(int i = 0 ; i < deleteFromGroups.size() ; i++)
					{
						//Use the delete user from group method. Token must be created for this action
						deleteUserFromGroup(username, deleteFromGroups.get(i), yourToken);
					}
					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}
					
					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					}

					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
					return true;	
				}
				else
				{
					return false; //User does not exist
					
				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	private List<String> listMembers(String group, UserToken token) {
		// Get the requester's name from the token
		String requester = token.getSubject();
		// Check if requester exists
		//Check if group exists
		if(my_gs.userList.checkUser(requester)) {
			// Does requester belong to the group?
			if(my_gs.groupList.getMembers(group) != null && my_gs.groupList.getMembers(group).contains(requester)) {
				// Check if user is allowed to list group members
				if(my_gs.userList.getUserOwnership(requester).contains(group)) {
				// Return the group's member list
					System.out.println("GroupList: " + my_gs.groupList.getMembers(group));
					ArrayList<String> members = new ArrayList<String>();
					for(String member:my_gs.groupList.getMembers(group)){
						members.add(member);
						System.out.println(member);
					}
					return members;
				}
			}
		}
		// The user does not exist
		return null;
	}

	private boolean addUserToGroup(String user, String group, UserToken token) {
		// Get the requester's name from the token
		String requester = token.getSubject();
		// Check if requester exists
		if(my_gs.userList.checkUser(requester)) {
			// Does requester belong to the group?
			//if(my_gs.groupList.getMembers(group) == null || my_gs.groupList.getMembers(group).contains(requester)) {
				// Check if user is allowed to add users to the group
				//if(my_gs.userList.getUserOwnership(requester).contains(group)) {
					// Does user exist?
					//if(my_gs.userList.checkUser(user)) {
						// Add user to the group
						my_gs.groupList.addMember(user, group);
						// Add group to the user's groups
						my_gs.userList.addGroup(user, group);
						return true;
					//}
				//}
			//}
		}
		// The user does not exist
		return false;
	}

	private boolean deleteUserFromGroup(String user, String group, UserToken token) {
		// Get the requester's name from the token
		String requester = token.getSubject();
		// Check if requester exists
		if(my_gs.userList.checkUser(requester)) {
			// Does requester belong to the group?
			if(my_gs.groupList.getMembers(group) != null && my_gs.groupList.getMembers(group).contains(requester)) {
				// Check if user is allowed to delete users from the group
				if(my_gs.userList.getUserOwnership(requester).contains(group)) {
					// Does user exist?
					if(my_gs.userList.checkUser(user)) {
						// Delete user from the group
						System.out.println("Userlist b4 rm: "+my_gs.userList.getUserGroups(user));
						my_gs.userList.removeGroup(user, group);
						System.out.println("Userlist after rm: "+my_gs.userList.getUserGroups(user));

						System.out.println("GroupList b4 rm: " + my_gs.groupList.getMembers(group));
						my_gs.groupList.removeMember(user, group);
						System.out.println("GroupList after rm: " + my_gs.groupList.getMembers(group));
						// Delete group from the user's groups
						return true;
					}
				}
			}
		}
		// The user does not exist
		return false;
	}
	
	//Private helper Method to generate RSA signature using private key & plaintext from user
	public static byte[] generatePkcs1Signature(PrivateKey rsaPrivate, byte[] input) throws Exception {
		Signature signature = Signature.getInstance("SHA384withRSA", "BC");
		signature.initSign(rsaPrivate);
		signature.update(input);
		return signature.sign();
	}

	private static byte[] decryptWithRSA(byte[] ciphertext, PublicKey key)
	{
		try
		{
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(ciphertext);
		}
		catch(Exception e)
		{
			System.out.println("Error in decrypting with RSA");
			return null;
		}
	}

	public static boolean verifyPkcs1Signature(PublicKey rsaPublic, byte[] input, byte[] encSignature) 
	throws Exception {
		Signature signature = Signature.getInstance("SHA384withRSA", "BC");
		signature.initVerify(rsaPublic);
		signature.update(input);
		return signature.verify(encSignature);
	}
	
	public static KeyPair generateRSAKeyPair()
		throws GeneralSecurityException
	{
	        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        	keyPairGenerator.initialize(2048);
        	return keyPairGenerator.generateKeyPair();	
	}

	private static byte[] encrypt(byte[] data, SecretKeySpec key)
	throws GeneralSecurityException
	{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}

	private static byte[] decrypt(byte[] data, SecretKeySpec key)
	throws GeneralSecurityException
	{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(data);
	}

	public static byte[] recipientAgreementBasic(PrivateKey recipientPrivate, PublicKey initiatorPublic)
	throws GeneralSecurityException
{
	KeyAgreement agreement = KeyAgreement.getInstance("DH", "BC");
	agreement.init(recipientPrivate);
	agreement.doPhase(initiatorPublic, true);
	SecretKey agreedKey = agreement.generateSecret("AES[256]");
	return agreedKey.getEncoded();
}

}
