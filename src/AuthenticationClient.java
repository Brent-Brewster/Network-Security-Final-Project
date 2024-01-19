/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
//import security
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
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

public class AuthenticationClient extends Client implements AuthenticationClientInterface {
	
	private KeyPair userkey = null;
	private SecretKeySpec sessionTokenWithAS = null;
	
	private static KeyPair generatDHKeyPair(DHParameterSpec PandG)
	throws GeneralSecurityException
	{
		KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DH", "BC");
 		keyPair.initialize(PandG);
 		return keyPair.generateKeyPair();
	} 


	public SecretKeySpec getSessionTokenWithAS(String username)
	{
		//perform diffie hellman
		Envelope env = new Envelope("getSessionTokenWithAS");
		DHParameterSpec PandG = null;
		KeyPair sessionTokenWithAS1 = null;
		try{
		PandG = generateParameters();
		//System.out.println("DH parameters" + PandG.getP().toString() + "		 " + PandG.getG().toString());
		sessionTokenWithAS1 = generateDHKeyPair(PandG);
		}
		catch(Exception e)
		{
			System.out.println("Error in generating the DH parameters and keys");
			return null;
		}
		//send the signed parameters to the AS it should know the users username at this time
		env.addObject(encryptWithRSA(PandG.getP().toByteArray(), userkey.getPrivate()));
		env.addObject(encryptWithRSA(PandG.getG().toByteArray(), userkey.getPrivate()));
		env.addObject(username);
		env.addObject(sessionTokenWithAS1.getPublic());
		//System.out.println("PandG.get L: " + PandG.getL());
		env.addObject(PandG.getL());

		//now that p and g are encryped and the Aserver already has authenticated the user and thus knows their public key
		//they can now send PandG signed/encrypted with their private key to the Aserer
		try{
		output.writeObject(env);
		}
		catch(Exception e)
		{
			System.out.println("Error in sending the DH parameters to the AS YIKES!");
			return null;
		}
		//now we wait for the AS to send us the public key of the server
		Envelope response = null;
		try{
		response = (Envelope)input.readObject();
		}
		catch(Exception e)
		{
			System.out.println("Error in reading the response from the AS");
			return null;
		}
		
		//get the AS public key
		PublicKey asPublicKey = null;
		try{
			FileInputStream fis = new FileInputStream("NotASPublicKey.bin");
			ObjectInputStream ois = new ObjectInputStream(fis);
			asPublicKey = (PublicKey)ois.readObject();
			ois.close();
		}
		catch(Exception e)
		{
			System.out.println("Error in reading the AS public key");
			return null;
		}

		if(response != null && response.getMessage().equals("ACPAGSIGNED"))
		{
			byte[] signedp = (byte[])response.getObjContents().get(0);
			byte[] signedg = (byte[])response.getObjContents().get(1);
			PublicKey ASDHPublicKey = (PublicKey)response.getObjContents().get(2);
			//System.out.println("ASDHPublicKey: " + ASDHPublicKey.toString());
			try{
			
			//KeyPair DHK = generateDHKeyPair(PandG);
			byte[] sharedSecrete = initiatorAgreement(sessionTokenWithAS1.getPrivate(), ASDHPublicKey);
			//System.out.println("Client shared secrete byte []: " + Arrays.toString(sharedSecrete));
			//System.out.println(sharedSecrete);
			sessionTokenWithAS = new SecretKeySpec(sharedSecrete, "AES");
			//System.out.println("Session token with AS generated it is: " + sessionTokenWithAS.toString());
			}
			catch(Exception e)
			{
				System.out.println("Error in generating the shared secrete");
				return null;
			}
			//decrypt the p and g values
			//the p and g values should be signed by the as on return to enusre our connection is with the AS
			try{
			if(verifyPkcs1Signature(asPublicKey, PandG.getP().toByteArray(), signedp ) && verifyPkcs1Signature(asPublicKey, PandG.getG().toByteArray(), signedg))
			{
				System.out.println("AS signature verified returning the session token");
				return sessionTokenWithAS;
			}
			else
			{
				System.out.println("AS signature not verified returning null");
				return null;
			}
			}
			catch(Exception e)
			{
				System.out.println("Error in verifying the signature of the AS");
				return null;
			}
		}
		return null;
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

	private static KeyPair generateDHKeyPair(DHParameterSpec PandG)
	throws GeneralSecurityException
	{
		KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DH", "BC");
	 	keyPair.initialize(PandG);
	 	return keyPair.generateKeyPair();
	}

	private static byte[] encryptWithRSA(byte[] plaintext, PrivateKey key)
	{
		try
		{
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(plaintext);
		}
		catch(Exception e)
		{
			System.out.println("Error in encrypting with RSA");
			return null;
		}
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

	public static byte[] initiatorAgreement(PrivateKey initiatorPrivate, PublicKey recipientPublic)
 	throws GeneralSecurityException
	{
 		KeyAgreement agreement = KeyAgreement.getInstance("DH", "BC");
 		agreement.init(initiatorPrivate);
 		agreement.doPhase(recipientPublic, true);
 		SecretKey agreedKey = agreement.generateSecret("AES[256]");
 		return agreedKey.getEncoded();
	} 

	public UserToken getToken(String username)
	 {
		KeyPair DHK = null;
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;
		 	
			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			System.out.println("Trying to read in the key");
			try{
				FileInputStream fis = new FileInputStream(username + "NotUserKeys.bin");
				ObjectInputStream ois = new ObjectInputStream(fis);
				userkey = (KeyPair)ois.readObject();
				System.out.println("Key read in");
				ois.close();
			}
			catch(Exception e)
			{
				System.out.println("User Key does not yet exist");
			}
			if(userkey != null)
				message.addObject(generatePkcs1Signature(userkey.getPrivate(), username.getBytes()));
			else
				message.addObject(null);
				output.writeObject(message);
		
			//Brent Started adding code here for DHKE
			response = (Envelope)input.readObject();
			if(response.getMessage().equals("DHKEP"))
			{
				System.out.println("client recived p and b");
				BigInteger p = (BigInteger)response.getObjContents().get(0); //prime mod val
				BigInteger g = (BigInteger)response.getObjContents().get(1); //generator value
				userkey = generateRSAKeyPair();
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream(username + "NotUserKeys.bin"));
					outStream.writeObject(userkey);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
				//Client needs to generate their own secrate value to use too here
				DHParameterSpec PandG = new DHParameterSpec(p, g);
				DHK = generatDHKeyPair(PandG);
				//send the public key to the AS
				message = new Envelope("DHKPK");
				message.addObject(DHK.getPublic());
				message.addObject(p);
				message.addObject(g);
				message.addObject(username);
				message.addObject(userkey.getPublic());
				System.out.println("Sending public key to the A server");
				output.writeObject(message);

			

			response = (Envelope)input.readObject();
			System.out.println(response.getMessage());

			if(response.getMessage().equals("PAIR"))
			{
				System.out.println("Key negotiation Completed recived key asking again for token");
				/*
				byte[] cipherText = (byte[])response.getObjContents().get(0);
				PublicKey asPublicKey = (PublicKey)response.getObjContents().get(1);
				//generate the shared secrete to decrypte the cpher 
				byte[] sharedSecrete = recipientAgreementBasic(DHK.getPrivate(), asPublicKey);
				SecretKeySpec secreteKeySpec = new SecretKeySpec(sharedSecrete, "AES");
				Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
				cipher.init(Cipher.DECRYPT_MODE, secreteKeySpec);
				byte[] plaintext = cipher.doFinal(cipherText);	//boom we have the rsa key pair hopefully
				*/
				
				
			}
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			message.addObject(generatePkcs1Signature(userkey.getPrivate(), username.getBytes()));
			//System.out.println("After the GetRequest");
			output.writeObject(message);
			response = (Envelope)input.readObject();
			System.out.println(response.getMessage());
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 2)
				{
					token = (UserToken)temp.get(0);
					PublicKey asPublicKey = (PublicKey)temp.get(1);
					try
					{
						FileOutputStream fos = new FileOutputStream("NotASPublicKey.bin");
						ObjectOutputStream oos = new ObjectOutputStream(fos);
						oos.writeObject(asPublicKey);
					}
					catch(Exception e)
					{
						System.out.println("ERROR WRITING TO ASPUBLICKEY FILE");
					}

					return token;
				}
			}
			}		
			//Brent Stopped adding code here for DHKE
			//Get the response from the server
			//response = (Envelope)input.readObject();
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 2)
				{
					token = (UserToken)temp.get(0);
					PublicKey asPublicKey = (PublicKey)temp.get(1);
					try
					{
						FileOutputStream fos = new FileOutputStream("NotASPublicKey.bin");
						ObjectOutputStream oos = new ObjectOutputStream(fos);
						oos.writeObject(asPublicKey);
					}
					catch(Exception e)
					{
						System.out.println("ERROR WRITING TO ASPUBLICKEY FILE");
					}
					return token;
				}
			}
			
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
		
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

	 public boolean createUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				//get the AS public key
				message.addObject(username); //Add user name string
				// byte[] encryptToken = token.getBytes();
				// byte[] encryptedToken = encrypt(encryptToken, sharedSecrete);
				message.addObject(encrypt(token.getBytes(), sessionTokenWithAS));
				message.addObject(token.getSubject());
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				
				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name
				message.addObject(encrypt(token.getBytes(), sessionTokenWithAS));  //Add requester's token
				message.addObject(token.getSubject());
				output.writeObject(message);
				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(encrypt(groupname.getBytes(), sessionTokenWithAS)); //Add the group name string
				message.addObject(encrypt(token.getBytes(), sessionTokenWithAS)); //Add the requester's token
				message.addObject(token.getSubject());
				output.writeObject(message); 
				

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					//System.out.println("response is good");
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				
				message = new Envelope("DGROUP");
				message.addObject(encrypt(groupname.getBytes(), sessionTokenWithAS)); //Add group name string
				message.addObject(encrypt(token.getBytes(), sessionTokenWithAS)); //Add requester's token
				message.addObject(token.getSubject());
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 
			 message = new Envelope("LMEMBERS");
			 message.addObject(encrypt(group.getBytes(), sessionTokenWithAS)); //Add group name string
			 message.addObject(encrypt(token.getBytes(), sessionTokenWithAS)); //Add requester's token
			 message.addObject(token.getSubject());
			 output.writeObject(message); 
			 
			 response = (Envelope)input.readObject();
			 
			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 { 
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }
	 
	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username); //Add user name string
				message.addObject(encrypt(groupname.getBytes(), sessionTokenWithAS)); //Add group name string
				message.addObject(encrypt(token.getBytes(), sessionTokenWithAS)); //Add requester's token
				message.addObject(token.getSubject());
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					System.out.println("Adding user to group successful");				
					return true;
				}
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
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

	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username); //Add user name string
				message.addObject(encrypt(groupname.getBytes(), sessionTokenWithAS)); //Add group name string
				message.addObject(encrypt(token.getBytes(), sessionTokenWithAS)); //Add requester's token
				message.addObject(token.getSubject());
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 // Method to see if our solution has 'x' leading zeros, only requires 1 hash for server to verify ** 
	 public boolean verifyPuzzle(String message, int hardness, String solution) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			// Our puzzle is our original message  + the ending nonce numbers appdned to it
			String puzzle = message + solution.substring(message.length());
			// Compute and check 
			byte[] hash = md.digest(puzzle.getBytes("UTF-8"));
			return checkLeadingZeros(hash, hardness);
		} catch (Exception e) {
			System.out.println("Error in verifying puzzle");
			return false;
		}
	}
	// Helper Method
    public boolean checkLeadingZeros(byte[] hash, int hardness) {
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

}
