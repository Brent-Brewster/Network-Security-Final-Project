import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;


public class Token implements UserToken, java.io.Serializable {


	private static final long serialVersionUID = 3102101517070539670L;
	private String issuer;
	private String subject;
	private ArrayList<String> groupList;
	private byte[] authSig;
	private final long tokenExpireTime = 3000000;
	private long expireTime;
	private String address;

	public byte[] getBytes() {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try{
		ObjectOutputStream out = new ObjectOutputStream(bos);
		out.writeObject(this);
		out.flush();
		return bos.toByteArray();
		}
		catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}
	
	public List<String> getGroups() {
		return groupList;
	}

	public String getIssuer() {
		return issuer;
	}

	public String getSubject() {
		return subject;
	}

	public String getAddress() {
		return address;
	}


	// Use this method to check if servers matches
	public String checkServerString() {
		String checkServer = "";
		checkServer += issuer + ":";
		checkServer += subject + ":";
		checkServer += address + ":";

		return checkServer;
	}
	
	public Token(String _issuer, String _subject, ArrayList<String> _groupList)
	{
		expireTime = refreshTime();
		issuer = _issuer;
		subject = _subject;
		groupList = new ArrayList<String>();	
		if (_groupList != null) {
		    groupList.addAll(_groupList);
		}
	}
	
	public boolean addGroup(String _group) {
		if (!groupList.contains(_group)) {
			groupList.add(_group);
			return true;
		}
		else return false;
	}

	public long refreshTime() {
		long currentTime = System.currentTimeMillis() + tokenExpireTime;
		return currentTime;
	}

	public boolean signToken(byte[] _signature)
	{
		if(!(_signature.equals(null))){
			authSig = _signature;
			return true;
		}
		else return false;
	}

	public byte[] getSignature()
	{
		return authSig;
	}


	@Override
	public boolean isTokenValid() {
		Long expirationTime = expireTime;
		if(expirationTime != null && expirationTime >= System.currentTimeMillis() ) {
			return true;
		} else {
			return false;
		}
	}



}
