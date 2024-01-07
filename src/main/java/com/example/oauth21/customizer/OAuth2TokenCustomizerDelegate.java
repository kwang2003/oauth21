package com.example.oauth21.customizer;

import com.example.oauth21.service.OidcUserInfoService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author kevin
 */
@Component
public class OAuth2TokenCustomizerDelegate implements OAuth2TokenCustomizer<JwtEncodingContext>, InitializingBean {
    private List<OAuth2TokenCustomizer<JwtEncodingContext>> oAuth2TokenCustomizers;
    @Autowired
    private OidcUserInfoService oidcUserInfoService;
    @Override
    public void customize(JwtEncodingContext context) {
        oAuth2TokenCustomizers.forEach(tokenCustomizer -> tokenCustomizer.customize(context));
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        oAuth2TokenCustomizers = List.of(
                new OAuth2AuthorizationCodeTokenCustomizer(),
                new OAuth2ClientCredentialsTokenCustomizer(),
                new OAuth2OIDCTokenCustomizer(oidcUserInfoService));
    }
}
