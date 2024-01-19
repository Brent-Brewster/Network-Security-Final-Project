/* Authentication server. Server loads the users and groups from UserList.bin and GroupList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator
 * and the owner of the ADMIN group.
 * If group list does not exist, it creates a new list and adds the ADMIN group.
 * On exit, the server saves the user and group lists to file. 
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;


public class AuthenticationServer extends Server {

	public static int SERVER_PORT;
	public ServerSocket serverSock;
	public UserList userList;
	public GroupList groupList;

	public AuthenticationServer() {
		super(SERVER_PORT, "ALPHA");
	}

	public AuthenticationServer(int _port) {
		super(_port, "ALPHA");
	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin
		// account needs to be created

		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		// This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListenerAS(this));
		
		// Open user file to get user list
		try {
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList) userStream.readObject();
		} catch (FileNotFoundException e) {
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();

			// Create a new list, add current user to the ADMIN group. They now own the
			// ADMIN group.
			userList = new UserList();
			userList.addUser(username);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
		} catch (IOException e) {
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		} catch (ClassNotFoundException e) {
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		// Open group file to get group list
		try {
			FileInputStream fis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis);
			groupList = (GroupList) groupStream.readObject();
		} catch (FileNotFoundException e) {
			System.out.println("GroupList File Does Not Exist. Creating GroupList...");
			System.out.println("No groups currently exist. Adding you to the ADMIN group.");

			String username;
			boolean error;
			// This loop tests that the username entered exists
			do {
				error = true;
				System.out.print("Enter your username: ");
				username = console.next();

				if (userList.checkUser(username)) {
					error = false;
				} else {
					System.out.println("That username does not exist");
				}
			} while (error);

			groupList = new GroupList();
			groupList.addGroup(username, "ADMIN");
		} catch (IOException e) {
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		} catch (ClassNotFoundException e) {
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		console.close();
		System.out.println("Welcome to the Authentication Server\nServer online");

		// Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		// This block listens for connections and creates threads on new connections
		try {

			serverSock = new ServerSocket(port);

			Socket sock = null;
			AuthenticationThread thread = null;

			while (true) {
				sock = serverSock.accept();
				thread = new AuthenticationThread(sock, this);
				thread.start();
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}

}

// This thread saves user and group lists
class ShutDownListenerAS extends Thread {
	public AuthenticationServer my_gs;

	public ShutDownListenerAS(AuthenticationServer _gs) {
		my_gs = _gs;
	}

	public void run() {
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try {
			my_gs.serverSock.close();
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		try {
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(my_gs.groupList);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread {
	public AuthenticationServer my_gs;

	public AutoSave(AuthenticationServer _gs) {
		my_gs = _gs;
	}

	public void run() {
		do {
			try {
				Thread.sleep(300000); // Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
				} catch (Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					outStream.writeObject(my_gs.groupList);
				} catch (Exception e) {
					System.err.println("Error with autosave");
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			} catch (Exception e) {
				System.out.println("Autosave Interrupted");
			}
		} while (true);
	}
}
