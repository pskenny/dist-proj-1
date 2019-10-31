package ie.gmit.ds;

import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;

import java.io.IOException;
import java.util.ArrayList;

/**
 * The following is a password server made on the example from lab notes:
 * https://github.com/john-french/distributed-systems-labs/tree/master/grpcIntro
 * 
 * @author Paul Kenny, G00326057
 *
 */

public class PasswordServer {

	public static ArrayList<byte[]> hashedPasswords;
	private Server server;

	public static void main(String[] args) throws IOException, InterruptedException {
		final PasswordServer server = new PasswordServer();
		hashedPasswords = new ArrayList<byte[]>();
		server.start();
		server.blockUntilShutdown();
	}

	private void start() throws IOException {
		/* The port on which the server should run */
		int port = 50051;
		server = ServerBuilder.forPort(port).addService(new PasswordServer.PasswordImpl()).build().start();
	}

	private void stop() {
		if (server != null) {
			server.shutdown();
		}
	}

	/**
	 * Await termination on the main thread since the grpc library uses daemon
	 * threads.
	 */
	private void blockUntilShutdown() throws InterruptedException {
		if (server != null) {
			server.awaitTermination();
		}
	}

	static class PasswordImpl extends PasswordGrpc.PasswordImplBase {
		@Override
		public void hash(HashRequest request, StreamObserver<HashReply> responseObserver) {

			// Generate salt and hashed password
			byte[] salt = Passwords.getNextSalt();
			byte[] hashedPassword = Passwords.hash(request.getPassword().toCharArray(), salt);

			// Generate reply
			HashReply reply = HashReply.newBuilder().setUserId(request.getUserId())
					.setHashPassword(hashedPassword.toString()).setSalt(salt.toString()).build();

			responseObserver.onNext(reply);
			responseObserver.onCompleted();

			// Add hashed password to list
			PasswordServer.hashedPasswords.add(hashedPassword);
		}

		@Override
		public void validate(ValidateRequest request, StreamObserver<ValidateReply> responseObserver) {
			// Get data from request
			char[] password = request.getPassword().toCharArray();
			byte[] salt = request.getSalt().getBytes();

			boolean flag = false;
			// Search known hashed passwords for the hashed password derived by request
			for (byte[] pass : PasswordServer.hashedPasswords) {
				if (Passwords.isExpectedPassword(password, salt, pass)) {
					// Hashed password found
					flag = true;
					break;
				}
			}

			// Generate reply
			ValidateReply reply = ValidateReply.newBuilder().setValid(flag).build();

			responseObserver.onNext(reply);
			responseObserver.onCompleted();
		}
	}
}