package com.example.oauth21.authentication.sms;

/**
 * 与短信验证码相关的sms
 * @author kevin
 */
public class RedisSmsConstant {
    /**
     * 短信验证码登录令牌桶令牌前缀
     */
    public static final String SMS_BUCKET_PREFIX = "oauth2:sms:token:";

    /**
     * 短信验证码前缀
     */
    public static final String SMS_CODE_PREFIX = "oauth2:sms:code";
}
