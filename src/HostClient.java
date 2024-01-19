
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.util.List;
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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

public class HostClient extends Client implements HostClientInterface{

	SecretKeySpec sharedSecrete;
    /**
     * Retrieves a list of resources that are allowed to be displayed
     * by members of the groups encoded in the supplied user token.
     *
     * @param token The UserToken object assigned to the user invoking this operation
     *
     * @return A list of SharedResource objects
     *
     */
    public List<SharedResource> listResources(final UserToken token)
    {
        try {
			Envelope message = null, e = null;
			// Tell the server to return the member list
			message = new Envelope("LFILES");
			byte[] encryptToken = token.getBytes();
			byte[] encryptedToken = encrypt(encryptToken, sharedSecrete);
			message.addObject(encryptedToken); // Add requester's token
			message.addObject(token.getSubject());
			output.writeObject(message);

			e = (Envelope) input.readObject();

			// If server indicates success, return the member list
			if (e.getMessage().equals("OK")) {
				return (List<SharedResource>) e.getObjContents().get(0); // This cast creates compiler warnings. Sorry.
			}

			return null;

		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
    }


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
    public boolean upload(final SharedResource localResource, final SharedResource remoteResource, final String group, final UserToken token)
    {
        String sourceFile = remoteResource.getID();
		String destFile = localResource.getID();
		FileInputStream fis;

		if (destFile.charAt(0) != '/') {
			destFile = "/" + destFile;
		}

		try {

			Envelope message = null, env = null;
			// Tell the server to return the member list
			try{
			fis = new FileInputStream(sourceFile);
			}
			catch(FileNotFoundException e)
			{
				System.out.println("File not found");
				return false;
			}
			message = new Envelope("UPLOADF");
			message.addObject(destFile);
			message.addObject(group);
			byte[] encryptToken = token.getBytes();
			byte[] encryptedToken = encrypt(encryptToken, sharedSecrete);
			System.out.println("/n");
			message.addObject(encryptedToken); // Add requester's token
			message.addObject(token.getSubject());
			//message.addObject(token); // Add requester's token
			output.writeObject(message);

			env = (Envelope) input.readObject();

			// If server indicates success, return the member list
			if (env.getMessage().equals("READY")) {
				System.out.printf("Meta data upload successful\n");

			} else {

				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}

			do {
				byte[] buf = new byte[4096];
				if (env.getMessage().compareTo("READY") != 0) {
					System.out.printf("Server error: %s\n", env.getMessage());
					return false;
				}
				message = new Envelope("CHUNK");
				
				
				int n = fis.read(buf); // can throw an IOException
				if (n > 0) {
					System.out.printf(".");
				} else if (n < 0) {
					System.out.println("Read error");
					fis.close();
					return false;
				}

				message.addObject(encrypt(buf, sharedSecrete));
				message.addObject(n);
				message.addObject(token.getSubject());

				output.writeObject(message);
				

				env = (Envelope) input.readObject();

			} while (fis.available() > 0);

			fis.close();

			if (env.getMessage().compareTo("READY") == 0) {

				message = new Envelope("EOF");
				output.writeObject(message);

				env = (Envelope) input.readObject();
				if (env.getMessage().compareTo("OK") == 0) {
					System.out.printf("\nFile data upload successful\n");
				} else {

					System.out.printf("\nUpload failed: %s\n", env.getMessage());
					return false;
				}

			} else {

				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}

		} catch (Exception e1) {
			System.err.println("Error: " + e1.getMessage());
			e1.printStackTrace(System.err);
			return false;
		}
		return true;
	}

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
    public boolean download(final SharedResource remoteResource, final SharedResource localResource, final UserToken token)
    {
        String sourceFile = remoteResource.getID();
		String destFile = localResource.getID();
        if (sourceFile.charAt(0) == '/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
		try {

			if (!file.exists()) {
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);
				Envelope env = new Envelope("DOWNLOADF"); // Success
				try{
				byte[] encryptsourceFile = sourceFile.getBytes();
				byte[] encryptedSF = encrypt(encryptsourceFile,sharedSecrete);
				env.addObject(encryptedSF);
				byte[] encryptToken = token.getBytes();
				byte[] encryptedToken = encrypt(encryptToken, sharedSecrete);
				env.addObject(encryptedToken); // Add requester's token
				env.addObject(remoteResource.getGroup());
				env.addObject(token.getSubject());
				output.writeObject(env);
				}catch(Exception e){
					System.out.println("Token/Source File Encryption Failed!");
				}
				

				env = (Envelope) input.readObject();

				while (env.getMessage().compareTo("CHUNK") == 0) {
					try{
					fos.write(decrypt((byte[])env.getObjContents().get(0),sharedSecrete), 0, (Integer) env.getObjContents().get(1));
					}catch(Exception e){
						System.out.println("Error with decrypting buf");
					}
					System.out.printf(".");
					env = new Envelope("DOWNLOADF"); // Success
					env.addObject(token.getSubject());
					output.writeObject(env);
					env = (Envelope) input.readObject();
				}
				fos.close();

				if (env.getMessage().compareTo("EOF") == 0) {
					fos.close();
					System.out.printf("\nTransfer successful file %s\n", sourceFile);
					env = new Envelope("OK"); // Success
					output.writeObject(env);
				} else {
					System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
					file.delete();
					return false;
				}
			}

			else {
				System.out.printf("Error couldn't create file %s\n", destFile);
				return false;
			}

		} catch (IOException e1) {

			System.out.printf("Error couldn't create file %s\n", destFile);
			return false;

		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
		return true;
	}

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
    public boolean delete(final SharedResource resource, final UserToken token)
    {
		String filename = resource.getID();
		String remotePath;
		if (filename.charAt(0) == '/') {
			remotePath = filename.substring(1);
		} else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF");
		byte[] encryptRP = remotePath.getBytes();
		byte[] encryptedRP = null;

		try{
			encryptedRP = encrypt(encryptRP, sharedSecrete);
		}
		catch(Exception e){
			System.out.println("Remote Path Encryption Failed!");
		}
		env.addObject(encryptedRP);
		byte[] encryptToken = token.getBytes();
		byte[] encryptedToken = null;
		try
		{
		encryptedToken = encrypt(encryptToken, sharedSecrete);
		}catch(Exception e){
			System.out.println("Token Encryption Failed!");
		}
		env.addObject(encryptedToken);
		env.addObject(token.getSubject());
		try {
			output.writeObject(env);
			env = (Envelope) input.readObject();

			if (env.getMessage().compareTo("OK") == 0) {
				System.out.printf("File %s deleted successfully\n", filename);
			} else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}

		return true;
    }

	public PublicKey getPublicKey() {
		Envelope env = new Envelope("GETPUBKEY");
		try {
			output.writeObject(env);
			env = (Envelope) input.readObject();
			if (env.getMessage().compareTo("OK") == 0) {
				return (PublicKey) env.getObjContents().get(0);
			} else {
				System.out.printf("Error getting public key (%s)\n", env.getMessage());
				return null;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
		
		return null;
	} 

	public void sendAuthsPKtoHostServer()
	{
		PublicKey asPub;
		try {
			FileInputStream fis = new FileInputStream("NotASPublicKey.bin");
			ObjectInputStream ois = new ObjectInputStream(fis);
			asPub = (PublicKey) ois.readObject();
			ois.close();
			Envelope message = new Envelope("ASPUBLIC");
			message.addObject(asPub);
			output.writeObject(message);
		} catch (Exception e) 
		{
			System.out.println("ASPUBLIC File Does Not Exist.");
			return;
		}
		
	}

	public boolean performDHWithHostServer(String username)
	throws Exception
	{
		Envelope env = new Envelope("DHI");
		DHParameterSpec dhParams = generateParameters();
		KeyPair DHKP = generateDHKeyPair(dhParams);
		env.addObject(DHKP.getPublic());
		env.addObject(dhParams.getP());
		env.addObject(dhParams.getG());
		System.out.println(username);
		env.addObject(username);
		output.writeObject(env);
		env = (Envelope) input.readObject();
		if(env.getMessage().equals("DONE"))
		{
			PublicKey HSPublicKey = (PublicKey) env.getObjContents().get(0);
			byte[] sharedSecrete1 = recipientAgreementBasic(DHKP.getPrivate(), HSPublicKey);
			sharedSecrete = new SecretKeySpec(sharedSecrete1, "AES");
			System.out.println("Host Client Shared Secret: "+sharedSecrete);
			return true;
		}
		else
		{
			System.out.println("Error performing DH with host server");
			return false;
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


	private static DHParameterSpec generateParameters()
	throws GeneralSecurityException
	{
		AlgorithmParameterGenerator algGen = AlgorithmParameterGenerator.getInstance("DH", "BC");
 		algGen.init(1024);
		System.out.println("Generating inside the generate method This may take a while...");
 		AlgorithmParameters dsaParams = algGen.generateParameters();
		System.out.println("Done with generation returning");
		return dsaParams.getParameterSpec(DHParameterSpec.class);
	}

	public byte[] getChallenge(byte[] encryptedChallenge) {
		Envelope env = new Envelope("GETCHALLENGE");
		env.addObject(encryptedChallenge);
		try {
			output.writeObject(env);
			env = (Envelope) input.readObject();
			System.out.println(env.getMessage());
			if (env.getMessage().compareTo("OK") == 0) {
				return (byte[]) env.getObjContents().get(0);
			} else {
				System.out.printf("Error getting challenge (%s)\n", env.getMessage());
				return null;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
		return null;
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