/* File worker thread handles the business of uploading, downloading, and 
 * removing files for clients with valid tokens 
 */

import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.ArrayList;
import java.lang.Thread;
import java.math.BigInteger;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

public class HostThread extends Thread
{
	private final Socket socket;
	private HostServer my_hs;

	public HostThread(Socket _socket, HostServer _hs)
	{
		socket = _socket;
		my_hs = _hs;
	}
	

	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());	
			// PublicKey ASPublic = null;
			ObjectInputStream fileStream;
			// 	try
			// 	{
			// 		FileInputStream fis = new FileInputStream("NotASPublicKey.bin");
			// 		fileStream = new ObjectInputStream(fis);
			// 		ASPublic = ((KeyPair)fileStream.readObject()).getPublic();
			// 	}
			// 	catch(FileNotFoundException e)
			// 	{
			// 		System.out.println("Authentication Server Public key NOT FOUND!");
			// 	}
			
				KeyPair HSRSAKeyPair;
				try
				{
					FileInputStream fis = new FileInputStream("NotHSRSAKey.bin");
					fileStream = new ObjectInputStream(fis);
					HSRSAKeyPair = (KeyPair)fileStream.readObject();
				}
				catch(FileNotFoundException e)
				{
					System.out.println("HSKEY does not exist creating one");
					HSRSAKeyPair = generateRSAKeyPair(); 
					try
					{
						ObjectOutputStream outStream; 
						outStream = new ObjectOutputStream(new FileOutputStream("NotHSRSAKey.bin"));
						outStream.writeObject(HSRSAKeyPair);
					}
					catch(Exception c)
					{
						System.err.println("Error: " + c.getMessage());
						c.printStackTrace(System.err);
					}
				}

			do
			{
				Envelope e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("GETPUBKEY")) {
					
					response = new Envelope("OK");
					response.addObject(HSRSAKeyPair.getPublic());
					output.writeObject(response);
				}

				if(e.getMessage().equals("GETCHALLENGE")) {
					response = new Envelope("Generic Response");
					if(e.getObjContents() == null) {
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else {
						Cipher cipher = Cipher.getInstance("RSA");
               			cipher.init(Cipher.DECRYPT_MODE, HSRSAKeyPair.getPrivate());
                		byte[] decryptedChallenge = cipher.doFinal((byte[])e.getObjContents().get(0));
						byte[] signedResponse = generatePkcs1Signature(HSRSAKeyPair.getPrivate(), decryptedChallenge);
						// send response as a digital signature
						response = new Envelope("OK");
						response.addObject(signedResponse);
					
					}
					output.writeObject(response);
				}
				if(e.getMessage().equals("DHI"))
				{
					response = new Envelope("Generic Response");
					if(e.getObjContents() == null) {
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else {
						BigInteger p = (BigInteger)e.getObjContents().get(1);
						BigInteger g = (BigInteger)e.getObjContents().get(2);
						String username = (String)e.getObjContents().get(3);
						//System.out.println("DH parameters received from client: " + p + " " + g + " " + username);
						DHParameterSpec PandG = new DHParameterSpec(p, g);
						KeyPair HSKeyPair = generateDHKeyPair(PandG);
						response = new Envelope("OK");
						response.addObject(HSKeyPair.getPublic());
						byte[] sharedSecrete = initiatorAgreement(HSKeyPair.getPrivate(), (PublicKey)e.getObjContents().get(0));
						SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecrete, "AES"); //generate the shared secrete key
						System.out.println("Host Server Shared Secret: "+secretKeySpec);
						System.out.println("Shared secret key generated for username: " + (String)e.getObjContents().get(3) + " and stored");
						if(secretKeySpec == null)
						{
							System.out.println("Shared secret key is NULL and were storing null");
						}
						my_hs.hostSessionTokenList.addHostSessionToken(username, secretKeySpec);
						System.out.println("Shared secret key generated and stored");
						response = new Envelope("DONE");
						response.addObject(HSKeyPair.getPublic());
						output.writeObject(response);
					}
				}
				if(e.getMessage().equals("LFILES"))
				{
						response = new Envelope("Generic Response"); //added to initialize response
				    // TODO: Write this handler 

					if(e.getObjContents() == null) {
						response = new Envelope("FAIL-BADTOKEN");
					}
					else{
						byte[] encryptedtokenData = (byte[])e.getObjContents().get(0);
						byte[] decryptedToken = decrypt(encryptedtokenData, my_hs.hostSessionTokenList.getHostSessionToken((String)e.getObjContents().get(1)));
						ByteArrayInputStream bos = new ByteArrayInputStream(decryptedToken);
						ObjectInputStream out = new ObjectInputStream(bos);
						UserToken t = (UserToken)out.readObject();
						//UserToken t = (UserToken)e.getObjContents().get(0);

						//Test code to verify a signature applied to a token and make sure it remains valid
						byte[] tokenData = (t.getIssuer()+t.getSubject()+t.getGroups()).getBytes(); 
						byte[] authSig = t.getSignature();

						PublicKey asPub;
						try {
							FileInputStream fis = new FileInputStream("NotASPublicKey.bin");
							ObjectInputStream ois = new ObjectInputStream(fis);
							asPub = (PublicKey) ois.readObject();
							ois.close();
						} catch (Exception e1) 
						{
							System.out.println("ASPUBLIC File Does Not Exist.");
							return;
						}

						if(!(verifyPkcs1Signature(asPub, tokenData, authSig))){
							System.out.println("Current token signature is invalid!");
						}
						else{
							System.out.println("Token signature successful!");
						}
						

						ArrayList<String> groupList = (ArrayList<String>)t.getGroups();
						ArrayList<SharedResource> allResources = (ArrayList<SharedResource>)HostServer.resourceList.getResources();
						ArrayList<SharedResource> allowedResources = new ArrayList<SharedResource>();
						
						if(allResources.size() == 0){
							response = new Envelope("FAIL-BADRESOURCELIST");
						}
						else{
						for(int i = 0; i < allResources.size(); i++){
							for(int j = 0; j < groupList.size(); j++){
								if(groupList.get(j).equals(allResources.get(i).getGroup())){
									allowedResources.add(allResources.get(i));
									}
								}
							}
							response = new Envelope("OK");
							response.addObject(allowedResources);
						}

					}
					output.writeObject(response);
				}
				if(e.getMessage().equals("ASPUBLIC"))
				{
					System.out.println("AS Public key recived");
					try
					{
						ObjectOutputStream outStream; 
						outStream = new ObjectOutputStream(new FileOutputStream("NotASPublicKey.bin"));
						PublicKey ASPublic1 = (PublicKey)e.getObjContents().get(0);
						outStream.writeObject(ASPublic1);
					}
					catch(Exception c)
					{
						System.out.println("ERROR WRITING TO FILE FOR ASPUBLIC KEY");
					}
				}
				if(e.getMessage().equals("UPLOADF"))
				{
						response = new Envelope("Generic Response"); //added to initialize response
					if(e.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							byte[] encryptedtokenData = (byte[])e.getObjContents().get(2);
							System.out.println("Encrypted token data: " + encryptedtokenData);
							byte[] decryptedToken = decrypt(encryptedtokenData, my_hs.hostSessionTokenList.getHostSessionToken((String)e.getObjContents().get(3)));
							ByteArrayInputStream in = new ByteArrayInputStream(decryptedToken);
							ObjectInputStream out = new ObjectInputStream(in);
							UserToken yourToken = (UserToken)out.readObject();//Extract token
							//UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token
							
							if (HostServer.resourceList != null && HostServer.resourceList.checkResource(remotePath)) {			//if the resource already exists
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}

							else if (!yourToken.getGroups().contains(group) && !yourToken.getGroups().contains("ADMIN")) {

								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED-Host"); //Success
								
							}
							else  {														//if the user has permission
								File file = new File("shared_resources/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); 	//Success
								output.writeObject(response); 			//send response to the HostClient.java

								e = (Envelope)input.readObject();
								while (e.getMessage().compareTo("CHUNK")==0) {
									byte[] encryptedChunk = (byte[])e.getObjContents().get(0);
									byte[] decryptedChunk = decrypt(encryptedChunk, my_hs.hostSessionTokenList.getHostSessionToken((String)e.getObjContents().get(2)));
									fos.write(decryptedChunk, 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									output.writeObject(response);
									e = (Envelope)input.readObject();
								}
								System.out.println(e.getMessage());
								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									HostServer.resourceList.addResource(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Fail
								}
								fos.close();
							}
						}
					}
					output.writeObject(response);
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {
					
					byte[] encryptedSF = (byte[])e.getObjContents().get(0);
					if(my_hs.hostSessionTokenList.getHostSessionToken((String)e.getObjContents().get(3)) == null)
					{
						System.out.println("Host DH Token is NULL");
					}
					byte[] decryptedSF = decrypt(encryptedSF,my_hs.hostSessionTokenList.getHostSessionToken((String)e.getObjContents().get(3)));
					String remotePath = new String(decryptedSF);

					byte[] encryptedtokenData = (byte[])e.getObjContents().get(1);
					byte[] decryptedToken = decrypt(encryptedtokenData, my_hs.hostSessionTokenList.getHostSessionToken((String)e.getObjContents().get(3)));
					ByteArrayInputStream in = new ByteArrayInputStream(decryptedToken);
					ObjectInputStream out = new ObjectInputStream(in);
					UserToken yourToken = (UserToken)out.readObject(); //Extract token

					SharedResource sf = HostServer.resourceList.getResource("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.writeObject(e);

					}
					else if (!yourToken.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", yourToken.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.writeObject(e);
					}
					else {

						try
						{
							File f = new File("shared_resources/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							output.writeObject(e);

						}
						else {
							FileInputStream fis = new FileInputStream(f);

							do {
								byte[] buf = new byte[4096];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								//e = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}
								String username = (String)e.getObjContents().get(3);
								byte[] encryptedBuf = encrypt(buf, my_hs.hostSessionTokenList.getHostSessionToken(username));
								e = new Envelope("CHUNK");
								e.addObject(encryptedBuf);
								e.addObject(n);

								output.writeObject(e);

								e = (Envelope)input.readObject();


							}
							while (fis.available()>0);

							fis.close();

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								output.writeObject(e);

								e = (Envelope)input.readObject();
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {
					byte[] encryptedRP = (byte[])e.getObjContents().get(0);
					byte [] decryptedRP = decrypt(encryptedRP, my_hs.hostSessionTokenList.getHostSessionToken((String)e.getObjContents().get(2)));
					String remotePath = new String(decryptedRP);
					byte[] encryptedtokenData = (byte[])e.getObjContents().get(1);
					byte[] decryptedToken = decrypt(encryptedtokenData, my_hs.hostSessionTokenList.getHostSessionToken((String)e.getObjContents().get(2)));
					ByteArrayInputStream in = new ByteArrayInputStream(decryptedToken);
					ObjectInputStream out = new ObjectInputStream(in);
					UserToken t = (UserToken)out.readObject(); //Extract token
					//Token t = (Token)e.getObjContents().get(1);
					SharedResource sf = HostServer.resourceList.getResource("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					}
					else {

						try
						{


							File f = new File("shared_resources/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								HostServer.resourceList.removeResource("/"+remotePath);
								e = new Envelope("OK");
							}
							else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					output.writeObject(e);

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	public static boolean verifyPkcs1Signature(PublicKey rsaPublic, byte[] input, byte[] encSignature) throws Exception {
		Signature signature = Signature.getInstance("SHA384withRSA", "BC");
		signature.initVerify(rsaPublic);
		signature.update(input);
		return signature.verify(encSignature);
	}

	//Private helper Method to generate RSA signature using private key & plaintext from user
	public static byte[] generatePkcs1Signature(PrivateKey rsaPrivate, byte[] input) throws Exception {
		Signature signature = Signature.getInstance("SHA384withRSA", "BC");
		signature.initSign(rsaPrivate);
		signature.update(input);
		return signature.sign();
	}

	public static KeyPair generateRSAKeyPair()
		throws GeneralSecurityException
	{
	        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        	keyPairGenerator.initialize(2048);
        	return keyPairGenerator.generateKeyPair();	
	}

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

}
