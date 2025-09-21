package pki.listener;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;

public class CustomEventListenerProvider implements EventListenerProvider {
    private static final String BACKEND_REGISTER_URL = "http://host.docker.internal:8081/user/register";
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Override
    public void onEvent(Event event) {
        if (event.getType() == org.keycloak.events.EventType.REGISTER) {
            String keycloakId = event.getUserId();
            String email = event.getDetails().get("email");
            String firstName = event.getDetails().get("firstName");
            String lastName = event.getDetails().get("lastName");
            String username = event.getDetails().get("username");

            System.out.println("User registration detected - ID: " + keycloakId + ", Email: " + email);

            try {
                // Escaping JSON values properly
                String json = String.format(
                        "{\"keycloakId\":\"%s\", \"email\":\"%s\", \"firstName\":\"%s\", \"lastName\":\"%s\", \"username\":\"%s\"}",
                        escapeJson(keycloakId),
                        escapeJson(email != null ? email : ""),
                        escapeJson(firstName != null ? firstName : ""),
                        escapeJson(lastName != null ? lastName : ""),
                        escapeJson(username != null ? username : "")
                );

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(BACKEND_REGISTER_URL))
                        .header("Content-Type", "application/json")
                        .timeout(Duration.ofSeconds(30))
                        .POST(HttpRequest.BodyPublishers.ofString(json))
                        .build();

                httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                        .thenAccept(response -> {
                            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                                System.out.println("User successfully saved in backend, status: " + response.statusCode());
                            } else {
                                System.err.println("Failed to save user in backend, status: " + response.statusCode() +
                                        ", body: " + response.body());
                            }
                        })
                        .exceptionally(throwable -> {
                            System.err.println("Error calling backend: " + throwable.getMessage());
                            throwable.printStackTrace();
                            return null;
                        });

            } catch (Exception e) {
                System.err.println("Exception in event listener: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
    }

    @Override
    public void close() {
        // Cleanup if needed
    }
}
