/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.social.google;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ErrorResponseException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import com.fasterxml.jackson.databind.JsonNode;

import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class GoogleIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

    public static final String AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
    public static final String TOKEN_URL = "https://oauth2.googleapis.com/token";
    public static final String PROFILE_URL = "https://openidconnect.googleapis.com/v1/userinfo";
    public static final String GROUPS_URL = "https://www.googleapis.com/admin/directory/v1/groups";
    public static final String DEFAULT_SCOPE = "openid profile email";
    public static final String GROUP_SCOPE = "https://www.googleapis.com/auth/admin.directory.group.readonly";

    private static final String OIDC_PARAMETER_HOSTED_DOMAINS = "hd";
    private static final String OIDC_PARAMETER_ACCESS_TYPE = "access_type";
    private static final String ACCESS_TYPE_OFFLINE = "offline";
    private static final String ATTRIBUTE_GOOGLE_GROUP = "google_group";

    public GoogleIdentityProvider(KeycloakSession session, GoogleIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    @Override
    protected String getUserInfoUrl() {
        String uri = super.getUserInfoUrl();
        if (((GoogleIdentityProviderConfig)getConfig()).isUserIp()) {
            ClientConnection connection = session.getContext().getConnection();
            if (connection != null) {
                uri = KeycloakUriBuilder.fromUri(super.getUserInfoUrl()).queryParam("userIp", connection.getRemoteAddr()).build().toString();
            }

        }
        logger.debugv("GOOGLE userInfoUrl: {0}", uri);
        return uri;
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }


    @Override
    public boolean isIssuer(String issuer, MultivaluedMap<String, String> params) {
        String requestedIssuer = params.getFirst(OAuth2Constants.SUBJECT_ISSUER);
        if (requestedIssuer == null) requestedIssuer = issuer;
        return requestedIssuer.equals(getConfig().getAlias());
    }


    @Override
    protected BrokeredIdentityContext exchangeExternalImpl(EventBuilder event, MultivaluedMap<String, String> params) {
        logger.info("*************************************************************");
        logger.info("Calling exchangeExternalImpl() in Google IDP.");
        logger.info("*************************************************************");
        return exchangeExternalUserInfoValidationOnly(event, params);
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        logger.info("*************************************************************");
        logger.info("Calling createAuthorizationUrl() in Google IDP.");
        logger.info("*************************************************************");

        UriBuilder uriBuilder = super.createAuthorizationUrl(request);
        final GoogleIdentityProviderConfig googleConfig = (GoogleIdentityProviderConfig) getConfig();
        String hostedDomain = googleConfig.getHostedDomain();

        if (hostedDomain != null) {
            uriBuilder.queryParam(OIDC_PARAMETER_HOSTED_DOMAINS, hostedDomain);
        }
        
        if (googleConfig.isOfflineAccess()) {
            uriBuilder.queryParam(OIDC_PARAMETER_ACCESS_TYPE, ACCESS_TYPE_OFFLINE);
        }
        
        return uriBuilder;
    }

    @Override
    protected JsonWebToken validateToken(final String encodedToken, final boolean ignoreAudience) {
        logger.info("*************************************************************");
        logger.info("Calling validateToken() in Google IDP.");
        logger.info("encodedToken: " + encodedToken);
        logger.info("*************************************************************");

        JsonWebToken token = super.validateToken(encodedToken, ignoreAudience);
        String hostedDomain = ((GoogleIdentityProviderConfig) getConfig()).getHostedDomain();

        if (hostedDomain == null) {
            return token;
        }

        Object receivedHdParam = token.getOtherClaims().get(OIDC_PARAMETER_HOSTED_DOMAINS);

        if (receivedHdParam == null) {
            throw new IdentityBrokerException("Identity token does not contain hosted domain parameter.");
        }

        if (hostedDomain.equals("*") || hostedDomain.equals(receivedHdParam))  {
            return token;
        }

        throw new IdentityBrokerException("Hosted domain does not match.");
    }

    @Override
	protected String getProfileEndpointForValidation(EventBuilder event) {
		return PROFILE_URL;
    }

    @Override
    protected void processAccessTokenResponse(BrokeredIdentityContext context, AccessTokenResponse response) {
        logger.info("*************************************************************");
        logger.info("Calling processAccessTokenResponse() in Google IDP.");
        logger.info("ID token: " + response.getIdToken());
        logger.info("Token: " + response.getToken());
        logger.info("*************************************************************");
        super.processAccessTokenResponse(context, response);

        logger.info("Calling getGroupInformation() with IdToken.");
        getGroupInformation(response.getIdToken());
        logger.info("Calling getGroupInformation() with Token.");
        getGroupInformation(response.getToken());
    }
    
    @Override
    protected Response exchangeSessionToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient,
            UserSessionModel tokenUserSession, UserModel tokenSubject) {
        logger.info("*************************************************************");
        logger.info("Calling exchangeSessionToken() in Google IDP.");
        logger.info("tokenUserSession: " + tokenUserSession);
        logger.info("tokenSubject: " + tokenSubject);
        logger.info("*************************************************************");
        return super.exchangeSessionToken(uriInfo, event, authorizedClient, tokenUserSession, tokenSubject);
    }

    @Override
    protected String getUsernameFromUserInfo(JsonNode userInfo) {
        logger.info("*************************************************************");
        logger.info("Calling getUsernameFromUserInfo() in Google IDP.");
        logger.info("userInfo: " + userInfo);
        logger.info("*************************************************************");
        return super.getUsernameFromUserInfo(userInfo);
    }

    @Override
    protected Response exchangeStoredToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient,
            UserSessionModel tokenUserSession, UserModel tokenSubject) {
        logger.info("*************************************************************");
        logger.info("Calling exchangeStoredToken() in Google IDP.");
        logger.info("tokenUserSession: " + tokenUserSession);
        logger.info("tokenSubject: " + tokenSubject);
        logger.info("*************************************************************");
        return super.exchangeStoredToken(uriInfo, event, authorizedClient, tokenUserSession, tokenSubject);
    }

    private void getGroupInformation(String token) {
        logger.info("*************************************************************");
        logger.info("Calling validateExternalTokenThroughUserInfo() in Google IDP.");
        logger.info("*************************************************************");
        
        GoogleIdentityProviderConfig config = (GoogleIdentityProviderConfig)getConfig();

        logger.info("Attempting to get group info. Default Scope: " + config.getDefaultScope().toString());

        // if (!config.getDefaultScope().contains(GROUP_SCOPE)) {
        //     return;
        // }
        
         // Get group info from endpoint
         SimpleHttp.Response response = null;
         int status = 0;
 
         try {
             response = SimpleHttp.doGet(GROUPS_URL + "?userKey=josue.lopes@randoli.ca", session)
                         .header("Authorization", "Bearer " + token).asResponse();
             status = response.getStatus();
             logger.info("Getting Google group info from endpoint. Status: " + status);
             logger.info("Response: " + response.asString());
         }
         catch (IOException e) {
             logger.debug("Failed to invoke group info", e);
         }
 
         if (status != 200) {
             logger.debug("Failed to invoke group info status: " + status);
         }
 
        //  // convert group info response into JSON object
        //  JsonNode groupProfile = null;
 
        //  try {
        //      groupProfile = response.asJson();
        //  } catch (IOException e) {
        //      logger.debug("Failed to invoke group info as JSON", e);
        //      event.detail(Details.REASON, "group info call failure");
        //      event.error(Errors.INVALID_TOKEN);
        //      throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);
        //  }
 
        //  List<String> groups = new ArrayList<String>();
 
        //  for (JsonNode groupNode : groupProfile.get("groups")) {
        //      groups.add(groupNode.get("id").asText());
        //  }
         
        //  user.setUserAttribute(ATTRIBUTE_GOOGLE_GROUP, groups);
        //  return user;
    }
}
