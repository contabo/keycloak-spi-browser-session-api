package com.contabo.keycloak.spi.realmresourceprovider.browseresssion;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class BrowserSessionRestProviderFactory implements RealmResourceProviderFactory {

  // determines it's id which is also the path for the rest endpoint
  // ... auth/realms/:realm/:id/
  public static final String RestPath = "browser-session";

  public RealmResourceProvider create(KeycloakSession session) {
    return new BrowserSessionRestProvider(session);
  }

  public void init(Scope config) {
    // NOP
  }

  public void postInit(KeycloakSessionFactory factory) {
    // NOP
  }

  public void close() {
    // NOP
  }

  public String getId() {
    return RestPath;
  }
}