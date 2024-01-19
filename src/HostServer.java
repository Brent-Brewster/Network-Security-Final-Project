/* FileServer loads files from ResourceList.bin.  Stores files in shared_resources directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;

public class HostServer extends Server {
	
	public static int SERVER_PORT;
	public static ResourceList resourceList;
	public ServerSocket serverSock;
	public HostSessionTokenList hostSessionTokenList;

	public HostServer() {
		super(SERVER_PORT, "ResourcePile");
	}

	public HostServer(int _port) {
		super(_port, "ResourcePile");
	}
	
	public void start() {
		String listFile = "ResourceList.bin";
		ObjectInputStream fileStream;
		hostSessionTokenList = new HostSessionTokenList();
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListener());
		runtime.addShutdownHook(catchExit);
		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(listFile);
			fileStream = new ObjectInputStream(fis);
			resourceList = (ResourceList)fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("ResourceList Does Not Exist. Creating ResourceList...");
			
			resourceList = new ResourceList();
			
		}
		catch(IOException e)
		{
			System.out.println("Error reading from ResourceList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from ResourceList file");
			System.exit(-1);
		}
		
		File file = new File("shared_resources");
		 if (file.mkdir()) {
			 System.out.println("Created new shared_resources directory");
		 }
		 else if (file.exists()){
			 System.out.println("Found shared_resources directory");
		 }
		 else {
			 System.out.println("Error creating shared_resources directory");				 
		 }
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFileServer aSave = new AutoSaveFileServer();
		aSave.setDaemon(true);
		aSave.start();
		
		
		boolean running = true;
		
		try
		{			
			serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
			
			Socket sock = null;
			Thread thread = null;
			
			while(running)
			{
				sock = serverSock.accept();
				thread = new HostThread(sock, this);
				thread.start();
			}
			
			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

//This thread saves user and group lists
class ShutDownListener implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("ResourceList.bin"));
			outStream.writeObject(HostServer.resourceList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFileServer extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("ResourceList.bin"));
					outStream.writeObject(HostServer.resourceList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
