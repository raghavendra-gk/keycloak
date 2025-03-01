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
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.util.LocaleUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriBuilder;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.net.URI;


import java.util.Locale;

//import static org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator.logger;
import static org.keycloak.authentication.authenticators.browser.ConditionalOtpFormAuthenticator.OtpDecision.ABSTAIN;
import static org.keycloak.authentication.authenticators.browser.ConditionalOtpFormAuthenticator.OtpDecision.SHOW_OTP;
import static org.keycloak.authentication.authenticators.browser.ConditionalOtpFormAuthenticator.OtpDecision.SKIP_OTP;
import static org.keycloak.models.utils.KeycloakModelUtils.getRoleFromString;

/**
 * An {@link OTPFormAuthenticator} that can conditionally require OTP authentication.
 * <p>
 * <p>
 * The decision for whether or not to require OTP authentication can be made based on multiple conditions
 * which are evaluated in the following order. The first matching condition determines the outcome.
 * </p>
 * <ol>
 * <li>User Attribute</li>
 * <li>Role</li>
 * <li>Request Header</li>
 * <li>Configured Default</li>
 * </ol>
 * <p>
 * If no condition matches, the {@link ConditionalOtpFormAuthenticator} fallback is to require OTP authentication.
 * </p>
 * <p>
 * <h2>User Attribute</h2>
 * A User Attribute like <code>otp_auth</code> can be used to control OTP authentication on individual user level.
 * The supported values are <i>skip</i> and <i>force</i>. If the value is set to <i>skip</i> then the OTP auth is skipped for the user,
 * otherwise if the value is <i>force</i> then the OTP auth is enforced. The setting is ignored for any other value.
 * </p>
 * <p>
 * <h2>Role</h2>
 * A role can be used to control the OTP authentication. If the user has the specified skip OTP role then OTP authentication is skipped for the user.
 * If the user has the specified force OTP role, then the OTP authentication is required for the user.
 * If not configured, e.g.  if no role is selected, then this setting is ignored.
 * <p>
 * </p>
 * <p>
 * <h2>Request Header</h2>
 * <p>
 * Request Headers are matched via regex {@link Pattern}s and can be specified as a whitelist and blacklist.
 * <i>No OTP for Header</i> specifies the pattern for which OTP authentication <b>is not</b> required.
 * This can be used to specify trusted networks, e.g. via: <code>X-Forwarded-Host: (1.2.3.4|1.2.3.5)</code> where
 * The IPs 1.2.3.4, 1.2.3.5 denote trusted machines.
 * <i>Force OTP for Header</i> specifies the pattern for which OTP authentication <b>is</b> required. Whitelist entries take
 * precedence before blacklist entries.
 * </p>
 * <p>
 * <h2>Configured Default</h2>
 * A default fall-though behaviour can be specified to handle cases where all previous conditions did not lead to a conclusion.
 * An OTP authentication is required in case no default is configured.
 * </p>
 *
 * @author <a href="mailto:thomas.darimont@gmail.com">Thomas Darimont</a>
 */
public class ConditionalOtpFormAuthenticator extends OTPFormAuthenticator {

    public static final String DEFAULT_ENTER_TOTP_MSG = "Please enter your One Time Password (OTP) generated via authenticator application";

    public static final String DEFAULT_INVALID_ATTEMPTS_MSG = "Attempt %d of 3";

    public static final String SKIP = "skip";

    public static final String FORCE = "force";

    public static final String OTP_CONTROL_USER_ATTRIBUTE = "otpControlAttribute";

    public static final String SKIP_OTP_ROLE = "skipOtpRole";

    public static final String FORCE_OTP_ROLE = "forceOtpRole";

    public static final String SKIP_OTP_FOR_HTTP_HEADER = "noOtpRequiredForHeaderPattern";

    public static final String FORCE_OTP_FOR_HTTP_HEADER = "forceOtpForHeaderPattern";

    public static final String DEFAULT_OTP_OUTCOME = "defaultOtpOutcome";

    enum OtpDecision {
        SKIP_OTP, SHOW_OTP, ABSTAIN
    }

    private static final String INCORRECT_ATTEMPT_COUNTER = "incorrectAttemptCounter";

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        if (context.getAuthenticationSession ().getAuthNote (INCORRECT_ATTEMPT_COUNTER) == null) {
            context.getAuthenticationSession ().setAuthNote (INCORRECT_ATTEMPT_COUNTER, "1");
          }

        AuthenticatorConfigModel model = context.getAuthenticatorConfig();
        Map<String, String> config = model != null? model.getConfig() : Collections.emptyMap();

        if (tryConcludeBasedOn(voteForUserOtpControlAttribute(context.getUser(), config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForUserRole(context.getRealm(), context.getUser(), config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForHttpHeaderMatchesPattern(context.getHttpRequest().getHttpHeaders().getRequestHeaders(), config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForDefaultFallback(config), context)) {
            return;
        }

        showOtpForm(context);
    }

    private OtpDecision voteForDefaultFallback(Map<String, String> config) {

        if (!config.containsKey(DEFAULT_OTP_OUTCOME)) {
            return ABSTAIN;
        }

        switch (config.get(DEFAULT_OTP_OUTCOME)) {
            case SKIP:
                return SKIP_OTP;
            case FORCE:
                return SHOW_OTP;
            default:
                return ABSTAIN;
        }
    }

    private boolean tryConcludeBasedOn(OtpDecision state, AuthenticationFlowContext context) {

        switch (state) {

            case SHOW_OTP:
                showOtpForm(context);
                return true;

            case SKIP_OTP:
                context.success();
                return true;

            default:
                return false;
        }
    }

    private boolean tryConcludeBasedOn(OtpDecision state) {

        switch (state) {

            case SHOW_OTP:
                return true;

            case SKIP_OTP:
                return false;

            default:
                return false;
        }
    }

    private void showOtpForm(AuthenticationFlowContext context) {
        super.authenticate(context);
    }

    private OtpDecision voteForUserOtpControlAttribute(UserModel user, Map<String, String> config) {

        if (!config.containsKey(OTP_CONTROL_USER_ATTRIBUTE)) {
            return ABSTAIN;
        }

        String attributeName = config.get(OTP_CONTROL_USER_ATTRIBUTE);
        if (attributeName == null) {
            return ABSTAIN;
        }

        Optional<String> value = user.getAttributeStream(attributeName).findFirst();
        if (!value.isPresent()) {
            return ABSTAIN;
        }

        switch (value.get().trim()) {
            case SKIP:
                return SKIP_OTP;
            case FORCE:
                return SHOW_OTP;
            default:
                return ABSTAIN;
        }
    }

    private OtpDecision voteForHttpHeaderMatchesPattern(MultivaluedMap<String, String> requestHeaders, Map<String, String> config) {

        if (!config.containsKey(FORCE_OTP_FOR_HTTP_HEADER) && !config.containsKey(SKIP_OTP_FOR_HTTP_HEADER)) {
            return ABSTAIN;
        }

        //Inverted to allow white-lists, e.g. for specifying trusted remote hosts: X-Forwarded-Host: (1.2.3.4|1.2.3.5)
        if (containsMatchingRequestHeader(requestHeaders, config.get(SKIP_OTP_FOR_HTTP_HEADER))) {
            return SKIP_OTP;
        }

        if (containsMatchingRequestHeader(requestHeaders, config.get(FORCE_OTP_FOR_HTTP_HEADER))) {
            return SHOW_OTP;
        }

        return ABSTAIN;
    }

    private boolean containsMatchingRequestHeader(MultivaluedMap<String, String> requestHeaders, String headerPattern) {

        if (headerPattern == null) {
            return false;
        }

        //TODO cache RequestHeader Patterns
        //TODO how to deal with pattern syntax exceptions?
        // need CASE_INSENSITIVE flag so that we also have matches when the underlying container use a different case than what
        // is usually expected (e.g.: vertx)
        Pattern pattern = Pattern.compile(headerPattern, Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

        for (Map.Entry<String, List<String>> entry : requestHeaders.entrySet()) {

            String key = entry.getKey();

            for (String value : entry.getValue()) {

                String headerEntry = key.trim() + ": " + value.trim();

                if (pattern.matcher(headerEntry).matches()) {
                    return true;
                }
            }
        }

        return false;
    }

    private OtpDecision voteForUserRole(RealmModel realm, UserModel user, Map<String, String> config) {

        if (!config.containsKey(SKIP_OTP_ROLE) && !config.containsKey(FORCE_OTP_ROLE)) {
            return ABSTAIN;
        }

        if (userHasRole(realm, user, config.get(SKIP_OTP_ROLE))) {
            return SKIP_OTP;
        }

        if (userHasRole(realm, user, config.get(FORCE_OTP_ROLE))) {
            return SHOW_OTP;
        }

        return ABSTAIN;
    }

    private boolean userHasRole(RealmModel realm, UserModel user, String roleName) {

        if (roleName == null) {
            return false;
        }

        RoleModel role = getRoleFromString(realm, roleName);
        if (role != null) {
            return user.hasRole(role);
        }
        return false;
    }

    private boolean isOTPRequired(KeycloakSession session, RealmModel realm, UserModel user) {
        MultivaluedMap<String, String> requestHeaders = session.getContext().getRequestHeaders().getRequestHeaders();
        List<Map<String,String>> configs = realm.getAuthenticatorConfigsStream().map(AuthenticatorConfigModel::getConfig)
                .filter(this::containsConditionalOtpConfig)
                .collect(Collectors.toList());
        if (configs.isEmpty()) {
            // no configuration at all means it is configured
            return true;
        }
        return configs.stream().anyMatch(config -> {
            if (tryConcludeBasedOn(voteForUserOtpControlAttribute(user, config))) {
                return true;
            }
            if (tryConcludeBasedOn(voteForUserRole(realm, user, config))) {
                return true;
            }
            if (tryConcludeBasedOn(voteForHttpHeaderMatchesPattern(requestHeaders, config))) {
                return true;
            }
            if (config.get(DEFAULT_OTP_OUTCOME) != null
                    && config.get(DEFAULT_OTP_OUTCOME).equals(FORCE)
                    && config.size() <= 1) {
                return true;
            }
            return voteForUserOtpControlAttribute(user, config) == ABSTAIN
                && voteForUserRole(realm, user, config) == ABSTAIN
                && voteForHttpHeaderMatchesPattern(requestHeaders, config) == ABSTAIN
                && (voteForDefaultFallback(config) == SHOW_OTP || voteForDefaultFallback(config) == ABSTAIN);
        });
    }

    private boolean containsConditionalOtpConfig(Map config) {
        return config.containsKey(OTP_CONTROL_USER_ATTRIBUTE)
            || config.containsKey(SKIP_OTP_ROLE)
            || config.containsKey(FORCE_OTP_ROLE)
            || config.containsKey(SKIP_OTP_FOR_HTTP_HEADER)
            || config.containsKey(FORCE_OTP_FOR_HTTP_HEADER)
            || config.containsKey(DEFAULT_OTP_OUTCOME);
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        if (!isOTPRequired(session, realm, user)) {
            user.removeRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        } else if (user.getRequiredActionsStream().noneMatch(UserModel.RequiredAction.CONFIGURE_TOTP.name()::equals)) {
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP.name());
        }
    }

      private static String getLocaleMessage (
      KeycloakSession session,
      Locale locale,
      String propertyName,
      String defaultMessage) {

    try {
      Theme theme = session.theme ().getTheme (Theme.Type.LOGIN);
      return theme.getMessages (locale).getProperty (propertyName);
    } catch (Exception e) {
      return defaultMessage;
    }
  }

    @Override
    public void action(AuthenticationFlowContext context) {
        // TODO Auto-generated method stub

            MultivaluedMap<String, String> inputData = context.getHttpRequest ()
      .getDecodedFormParameters ();
    String otp = inputData.getFirst ("otp");

    String credentialId = inputData.getFirst ("selectedCredentialId");

    boolean valid = context.getUser ()
      .credentialManager ()
      .isValid (new UserCredentialModel (
        credentialId,
        this.getCredentialProvider (context.getSession ()).getType (),
        otp
      ));

    if (!valid) {
      KeycloakSession kcSession = context.getSession ();
      Locale locale = kcSession.getContext ().resolveLocale (context.getUser ());
      String softOtpLabel = getLocaleMessage (kcSession, locale, "softOTPHeaderMsg", DEFAULT_ENTER_TOTP_MSG);

      int incorrectAttemptCounter = Integer.parseInt (context.getAuthenticationSession ()
        .getAuthNote (INCORRECT_ATTEMPT_COUNTER));
      incorrectAttemptCounter++;

      if (incorrectAttemptCounter == 4) {
        Response response = restartLogin (context.getAuthenticationSession (), context.getSession ());
        context.forceChallenge (response);
        return;
      }

      if (incorrectAttemptCounter > 1) {
        // The base string sentence (Constants.DEFAULT_ENTER_TOTP_MSG) should end with "."
        String attemptLabel = ". " + getLocaleMessage (
            kcSession,
            locale,
            "invalidAttemptsLabel",
            DEFAULT_INVALID_ATTEMPTS_MSG);
        softOtpLabel += String.format (attemptLabel, incorrectAttemptCounter);
      }

      context.form ().setAttribute ("softotplabel", softOtpLabel);

      context.getAuthenticationSession ()
        .setAuthNote (INCORRECT_ATTEMPT_COUNTER, String.valueOf (incorrectAttemptCounter));
    }

        super.action(context);
    }


    
      public static Response restartLogin (AuthenticationSessionModel authSession,
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
