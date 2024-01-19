/* Driver program for FileSharing File Server */

public class RunHostServer {
	
	public static void main(String[] args) {
		if (args.length > 0) {
			try {
				HostServer server = new HostServer(Integer.parseInt(args[0]));
				server.start();
			}
			catch (NumberFormatException e) {
				System.out.printf("Enter a valid port number or pass no arguments to use the default port (%d)\n", HostServer.SERVER_PORT);
			}
		}
		else {
			HostServer server = new HostServer();
			server.start();
		}
	}

}
