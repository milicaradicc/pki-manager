package pki.listener;

import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public abstract class CustomEventListenerProviderFactory implements EventListenerProviderFactory {

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new CustomEventListenerProvider();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Post initialization logic if needed
    }

    @Override
    public void close() {
        // Cleanup if needed
    }

    @Override
    public String getId() {
        return "custom-event-listener";
    }
}