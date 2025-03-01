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

package org.keycloak.authentication.authenticators.browser;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.organization.protocol.mappers.oidc.OrganizationScope;
import org.keycloak.organization.utils.Organizations;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.apache.commons.lang3.StringUtils;

import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;
import static org.keycloak.protocol.oidc.OIDCLoginProtocol.PROMPT_PARAM;
import static org.keycloak.protocol.oidc.OIDCLoginProtocol.PROMPT_VALUE_CONSENT;

import java.net.URI;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class CookieAuthenticator implements Authenticator {

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(context.getSession(),
                context.getRealm(), true);
        if (authResult == null) {
            context.attempted();
        } else {
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            LoginProtocol protocol = context.getSession().getProvider(LoginProtocol.class, authSession.getProtocol());
            authSession.setAuthNote(Constants.LOA_MAP, authResult.getSession().getNote(Constants.LOA_MAP));
            context.setUser(authResult.getUser());
            AcrStore acrStore = new AcrStore(context.getSession(), authSession);


                  /*
       ******************* Start :  Customization *******************
       *
       * If login_hint param is passed and prompt param is either not passed or passed with
       * value "none", then we need to compare the loginId of login_hint param vs that of
       * current user session. If matching, then we shall ignore. Else, we need to forcefully
       * set the prompt value to "login" to force re-authentication.
       * */
      KeycloakSession session = context.getSession ();
      MultivaluedMap<String, String> queryParameters =
        session.getContext ().getUri ().getQueryParameters ();
      if (isOnlyLoginHintPresent (queryParameters)) {
        String userName = queryParameters.getFirst (LOGIN_HINT);
        if (!userName.equalsIgnoreCase (authResult.getUser ().getUsername ())) {
          authSession.setClientNote (PROMPT, "login");
        } else {
          // If the user session is already established and the same user is coming again
          // through via "login_hint", then check for save_consent flag.
          // If consent is not saved, force the user to consent screen
          promptToConsentPageIfConsentNotSaved (context, authSession, session);
        }
      } else if (queryParameters != null && !queryParameters.containsKey (PROMPT)) {
        // Both login_hint and prompt are not present. In this case,
        // check for save_consent flag for the authenticated user.
        // If consent is not saved, force the user to consent screen
        promptToConsentPageIfConsentNotSaved (context, authSession, session);
      }
      /*
       ******************* End : HSP IAM Customization *******************
       * */
            // Cookie re-authentication is skipped if re-authentication is required
            if (protocol.requireReauthentication(authResult.getSession(), authSession)) {
                // Full re-authentication, so we start with no loa
                acrStore.setLevelAuthenticatedToCurrentRequest(Constants.NO_LOA);
                authSession.setAuthNote(AuthenticationManager.FORCED_REAUTHENTICATION, "true");
                context.setForwardedInfoMessage(Messages.REAUTHENTICATE);

         /*
         ******************* Start : Customization *******************
         *
         * When re-authentication is required but another user session already exists, KC
         * shows an intermediate page wherein we need to click one more button to restart
         * login. Hence, we need to override this behaviour and forcefully restart login
         * */
            Response response = restartLogin (context.getAuthenticationSession (), context.getSession ());
            context.forceChallenge (response);
            /*
            ******************* End :  Customization *******************
            */

                context.attempted();
            } else if(AuthenticatorUtil.isForkedFlow(authSession)){
                context.attempted();
            } else {
                String topLevelFlowId = context.getTopLevelFlow().getId();
                int previouslyAuthenticatedLevel = acrStore.getHighestAuthenticatedLevelFromPreviousAuthentication(topLevelFlowId);
                AuthenticatorUtils.updateCompletedExecutions(context.getAuthenticationSession(), authResult.getSession(), context.getExecution().getId());

                if (acrStore.getRequestedLevelOfAuthentication(context.getTopLevelFlow()) > previouslyAuthenticatedLevel) {
                    // Step-up authentication, we keep the loa from the existing user session.
                    // The cookie alone is not enough and other authentications must follow.
                    acrStore.setLevelAuthenticatedToCurrentRequest(previouslyAuthenticatedLevel);

                    if (authSession.getClientNote(Constants.KC_ACTION) != null) {
                        context.setForwardedInfoMessage(Messages.AUTHENTICATE_STRONG);
                    }

                    context.attempted();
                } else {
                    // Cookie only authentication
                    acrStore.setLevelAuthenticatedToCurrentRequest(previouslyAuthenticatedLevel);
                    authSession.setAuthNote(AuthenticationManager.SSO_AUTH, "true");
                    context.attachUserSession(authResult.getSession());

           /*
           ******************* Start : Customization *******************
           *
           * Adding below block for saml flow where assertion should be always given when
           * session is active
           * */
          boolean samlFlow = false;

          if (queryParameters != null &&
            queryParameters.containsKey (AdapterConstants.KC_IDP_HINT)) {
            String kcIdpHint = queryParameters.getFirst (AdapterConstants.KC_IDP_HINT);
            IdentityProviderModel idpConfig =
                context.getRealm ().getIdentityProviderByAlias (kcIdpHint);
            if (idpConfig != null && "saml".equalsIgnoreCase (idpConfig.getProviderId ())) {
              samlFlow = true;
            }
          }

          if (samlFlow) {
            context.attempted ();
          } else {
            context.success ();
          }
          /*
           ******************* End : Customization *******************
           * */

                    if (isOrganizationContext(context)) {
                        // if re-authenticating in the scope of an organization, an organization must be resolved prior to authenticating the user
                        context.attempted();
                    } else {
                        context.success();
                    }
                }
            }
        }

    }

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {

    }

    private boolean isOrganizationContext(AuthenticationFlowContext context) {
        KeycloakSession session = context.getSession();

        if (Organizations.isEnabledAndOrganizationsPresent(session)) {
            return OrganizationScope.valueOfScope(session) != null;
        }

        return false;
    }

    private static final String LOGIN_HINT = "login_hint";
    private static final String PROMPT = "prompt";

   private boolean isOnlyLoginHintPresent (MultivaluedMap<String, String> queryParameters) {

    return queryParameters != null && queryParameters.containsKey (LOGIN_HINT)
        && StringUtils.isNotBlank (queryParameters.getFirst (LOGIN_HINT))
        && (!queryParameters.containsKey (PROMPT) || (queryParameters.containsKey (PROMPT)
            && "none".equals (queryParameters.getFirst (PROMPT))));
  }

  private void promptToConsentPageIfConsentNotSaved (
      AuthenticationFlowContext context,
      AuthenticationSessionModel authSession,
      KeycloakSession session) {

    String userId = context.getUser ().getId ();
    String clientId = authSession.getClient ().getId ();
    //get the consent from separate consent store
    boolean isConsentSaved = null != session.users().getConsentByClient(null, userId, clientId);
    if (!isConsentSaved) {
      // save_consent is false. Let's delete all the granted consents and
      // allow KC to re-perform adding consent to clients .
      session.users ().revokeConsentForClient (session.getContext ().getRealm (), userId, clientId);

      String promptParam = context.getAuthenticationSession ().getClientNote (PROMPT_PARAM);
      // Let's add prompt=consent forcefully since the consent is not saved.
      promptParam = StringUtils.isBlank (promptParam) ? PROMPT_VALUE_CONSENT
          : promptParam + " " + PROMPT_VALUE_CONSENT;
      context.getAuthenticationSession ().setClientNote (PROMPT_PARAM, promptParam);
    }
  }
    
  private static Response restartLogin (AuthenticationSessionModel authSession,
  KeycloakSession keycloakSession) {

  KeycloakContext keycloakContext = keycloakSession.getContext ();
  URI absolutePath = keycloakContext.getUri ().getAbsolutePath ();
  String host = StringUtils.substringBefore (absolutePath.toString (), "/realms");
  String realmName = keycloakContext.getRealm ().getName ();
  String url = host + "/realms/" + realmName + "/login-actions/restart";

  UriBuilder uriBuilder = UriBuilder.fromUri (url);
  uriBuilder.queryParam ("client_id", authSession.getClient ().getClientId ());
  uriBuilder.queryParam ("tab_id", authSession.getTabId ());
  uriBuilder.queryParam (
    "client_data",
    AuthenticationProcessor.getClientData (keycloakSession, authSession)
  );
  uriBuilder.queryParam ("skip_logout", "false");

  return Response.seeOther (uriBuilder.build ()).build ();
}

}
