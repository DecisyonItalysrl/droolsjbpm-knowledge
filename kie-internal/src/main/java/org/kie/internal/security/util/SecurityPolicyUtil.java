package org.kie.internal.security.util;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class SecurityPolicyUtil {

	public static File getPolicyFromHTTP(String policyURL, String userName, String password) throws IllegalStateException {
		
		File file = null;
		OutputStream fileOut = null;
		try { 
			file = File.createTempFile("kie", "policy");
			fileOut = new BufferedOutputStream(new FileOutputStream(file));
			URI url = URI.create(policyURL);
			readHTTPResource(url, userName, password, fileOut);
			fileOut.flush();
			
			return file;
		} catch(Exception e) {
			throw new IllegalStateException(e);
		} finally {
			if(fileOut != null)
				try {
					fileOut.close();
				} catch (IOException e) {}
		}
	}

	public static void readHTTPResource(URI url, String userName, String password, OutputStream out) throws Exception {
		
		CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
		Credentials credentials = new UsernamePasswordCredentials("","");
		credentialsProvider.setCredentials(AuthScope.ANY, credentials);
		CloseableHttpClient client = HttpClients.custom().setDefaultCredentialsProvider(credentialsProvider).build();
		CloseableHttpResponse response = null;
		try {
			response = client.execute(new HttpGet(url));
			if(response.getStatusLine().getStatusCode() != 200)
				throw new IllegalArgumentException("Cannot read HTTP Resource");

			response.getEntity().writeTo(out);
		} catch (Exception e) {
			throw e;
		} finally {
			if(response != null)
				try {
					response.close();
				} catch (IOException e) {}
		}
		try {
			client.close();
		} catch (IOException e) {}
	}


}
