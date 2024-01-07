package com.example.oauth21.customizer;

import com.example.oauth21.service.OidcUserInfoService;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * @author kevin
 */
public class OAuth2OIDCTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    private OidcUserInfoService userInfoService;
    public OAuth2OIDCTokenCustomizer(OidcUserInfoService userInfoService){
        this.userInfoService = userInfoService;
    }
    @Override
    public void customize(JwtEncodingContext jwtContext) {
        if(OidcParameterNames.ID_TOKEN.equalsIgnoreCase(jwtContext.getTokenType().getValue())){
            OidcUserInfo userInfo = userInfoService.loadUser(
                    jwtContext.getPrincipal().getName());
            jwtContext.getClaims().claims(claims ->
                    claims.putAll(userInfo.getClaims()));
        }
    }
}
