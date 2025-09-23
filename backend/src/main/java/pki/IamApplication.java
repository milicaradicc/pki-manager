package pki;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class IamApplication {

	public static void main(String[] args) {
		System.setProperty("javax.net.ssl.trustStore", "c:\\certs\\keycloak-truststore.jks");
		System.setProperty("javax.net.ssl.trustStorePassword", "trustpass");

		SpringApplication.run(IamApplication.class, args);
	}

}
