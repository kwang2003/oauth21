package com.example.oauth21.authentication.sms;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * 短信认证相关的常量定义
 * @author kevin
 */
public class OAuth2SmsConstant {
    public static final AuthorizationGrantType SMS = new AuthorizationGrantType("sms");

    /**
     * 手机号参数名
     */
    public static final String PARAMS_MOBILE = "mobile";
    /**
     * 手机验证码
     */
    public static final String PARAMS_CODE = "code";
}
