package com.example.oauth21.customizer;

import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Map;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;

/**
 * @author kevin
 */
public class OAuth2ClientCredentialsTokenCustomizer  implements OAuth2TokenCustomizer<JwtEncodingContext> {
    @Override
    public void customize(JwtEncodingContext jwtContext) {
        if (CLIENT_CREDENTIALS.equals(jwtContext.getAuthorizationGrantType()) && ACCESS_TOKEN.equals(
                jwtContext.getTokenType())) {
            OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication = jwtContext.getAuthorizationGrant();
            Map<String, Object> additionalParameters = clientCredentialsAuthentication.getAdditionalParameters();
            additionalParameters.forEach((key, value) -> jwtContext.getClaims().claim(key, value));
        }
    }
}
