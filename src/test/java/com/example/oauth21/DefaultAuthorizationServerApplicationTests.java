package com.example.oauth21;

import com.gargoylesoftware.htmlunit.WebClient;
import com.google.common.base.Charsets;
import com.google.common.collect.Lists;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class DefaultAuthorizationServerApplicationTests {
    private static final String AUTHORIZATION_URL = "http://localhost:9000";
    private static final String REDIRECT_URI = "http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc";
    private static final String AUTHORIZATION_REQUEST = UriComponentsBuilder
            .fromPath("/oauth2/authorize")
            .queryParam("response_type","code")
            .queryParam("client_id","messaging-client")
            .queryParam("scope","openid")
            .queryParam("state","some-state")
            .queryParam("redirect_uri",REDIRECT_URI)
            .toUriString();
    private static final String AUTHORIZATION_TOKEN_ENDPOINT = AUTHORIZATION_URL +"/oauth2/token";

    @Autowired
    private WebClient webClient;

    @BeforeEach
    public void setUp(){
        this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(true);
        this.webClient.getOptions().setRedirectEnabled(true);
        this.webClient.getCookieManager().clearCookies();
    }

    @Test
    @SneakyThrows
    @DisplayName("测试客户端模式-使用post提交client_id和client_secret参数")
    void testClientMode(){
        //需要客户端开启client_secret_post 模式
        String clientId = "messaging-client";
        String clientSecret = "secret";
        HttpClient httpClient = HttpClients.createDefault();
        HttpPost post = new HttpPost(AUTHORIZATION_TOKEN_ENDPOINT);
        post.setHeader("Content-Type", "application/x-www-form-urlencoded");
        List<NameValuePair> params = Lists.newLinkedList();
        params.add(new BasicNameValuePair("grant_type","client_credentials"));
        params.add(new BasicNameValuePair("client_id",clientId));
        params.add(new BasicNameValuePair("client_secret",clientSecret));
        post.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));
        HttpEntity entity = httpClient.execute(post).getEntity();
        String response = EntityUtils.toString(entity,Charsets.UTF_8);
        log.info(response);
    }

    @Test
    @SneakyThrows
    @DisplayName("测试客户端模式-使用http basic方式提交client_id和client_secret")
    void testClientMode2(){
        // 需要客户端开启client_secret_basic
        String clientId = "messaging-client";
        String clientSecret = "secret";
        HttpClient httpClient = HttpClients.createDefault();
        HttpPost post = new HttpPost(AUTHORIZATION_TOKEN_ENDPOINT);
        post.setHeader("Content-Type", "application/x-www-form-urlencoded");
        post.setHeader("Authorization","Basic "+ Base64.getEncoder().encodeToString(String.format("%s:%s",clientId,clientSecret).getBytes(StandardCharsets.UTF_8)));
        List<NameValuePair> params = Lists.newLinkedList();
        params.add(new BasicNameValuePair("grant_type","client_credentials"));
        params.add(new BasicNameValuePair("client_id",clientId));
        params.add(new BasicNameValuePair("client_secret",clientSecret));
        post.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));
        HttpEntity entity = httpClient.execute(post).getEntity();
        String response = EntityUtils.toString(entity,Charsets.UTF_8);
        log.info(response);
    }

    /**
     * ①客户端jwt的格式，签名使用服务器端一样的签名算法和公约私钥
     * ②客户端的配置中需要包含"settings.client.token-endpoint-authentication-signing-algorithm":"HS256"
     * ③jwt中需要包含如下格式的信息
     * iss 必填. client_id.
     * sub 必填. client_id
     * aud 必填. token端点的url
     * jti 必填. JWT ID
     * exp 必填. 过期时间
     * iat 可选. jwt生成时间
     */
    @Test
    @SneakyThrows
    @DisplayName("测试客户端模式-使用private_key_jwt方式提交client_id和client_secret")
    void testClientMode3(){
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtZXNzYWdpbmctY2xpZW50IiwiaXNzIjoibWVzc2FnaW5nLWNsaWVudCIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMC9vYXV0aDIvdG9rZW4iLCJqdGkiOiIxMjM0NTY3IiwiaWF0IjoxNjgyMjM5MDIyLCJleHAiOjMwODIyMzkwMjJ9.InE71TMZOjv3PllNy9xWbOF41AWxdRwd8Y4EcaTlnhEqp1QZeQ7avQseTweOydQh0McqN2FUNAB4hhwg9o4WctCzMveW82lmpGmAGxFsAAM1hcVScygrc5sSVPXrTlsdbbGs-ulbJ50nyn8zcNs_-uXmX0JdZREa2xdOwEpT8_YtL8OEUcGtwE0stGRtdtOQLPdrpmCnhr-piDlbZ8ll5PuxbIaBCCJvx4_Y0hbtJ3u5meBQjcrk2NRovD4AZjMJjLot629l-s0wvY3GbWwpuUJrEIge8vmvInIAws7DusGsLVsusunpoh1MLsMjOu9NcozH1fnGT2vdNlfT3Xx1Bg";
        // 需要客户端开启client_secret_basic
        String clientId = "messaging-client";
        HttpClient httpClient = HttpClients.createDefault();
        HttpPost post = new HttpPost(AUTHORIZATION_TOKEN_ENDPOINT);
        post.setHeader("Content-Type", "application/x-www-form-urlencoded");
        List<NameValuePair> params = Lists.newLinkedList();
        params.add(new BasicNameValuePair("grant_type","client_credentials"));
        params.add(new BasicNameValuePair("client_id",clientId));
        params.add(new BasicNameValuePair("client_assertion_type","urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
        params.add(new BasicNameValuePair("client_assertion",jwt));
        post.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));
        HttpEntity entity = httpClient.execute(post).getEntity();
        String response = EntityUtils.toString(entity,Charsets.UTF_8);
        log.info(response);
    }


    @Test
    @SneakyThrows
    @DisplayName("授权码模式")
    public void testCodeMode(){
        String url = "localhost:9000/oauth2/authorize?client_id=messaging-client&response_type=code&scope=openid&state=aaabbccdd&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fauthorized";

        //如下是回调方url响应逻辑
        String demo = """
                @Slf4j
                @RestController
                public class CallbackController {
                    private Gson gson = new GsonBuilder().create();
                                
                    @SneakyThrows
                    @GetMapping("/authorized")
                    public String callback(String code,String state){
                        log.info("code={},state={}",code,state);
                                
                        String clientId = "messaging-client";
                        String clientSecret = "secret";
                        HttpClient httpClient = HttpClients.createDefault();
                        List<NameValuePair> pairs = Lists.newArrayList();
                        pairs.add(new BasicNameValuePair("grant_type","authorization_code"));
                        pairs.add(new BasicNameValuePair("client_id",clientId));
                        pairs.add(new BasicNameValuePair("client_secret",clientSecret));
                        pairs.add(new BasicNameValuePair("code",code));
                        pairs.add(new BasicNameValuePair("redirect_uri","http://127.0.0.1:8080/authorized"));
                        HttpPost httpPost = new HttpPost("http://localhost:9000/oauth2/token");
                        httpPost.setHeader("Content-Type","application/x-www-form-urlencoded");
                        httpPost.setEntity(new UrlEncodedFormEntity(pairs,StandardCharsets.UTF_8));
                        HttpEntity entity = httpClient.execute(httpPost).getEntity();
                        String content = EntityUtils.toString(entity, StandardCharsets.UTF_8);
                        log.info("{}",content);
                                
                        JsonObject json = gson.fromJson(content,JsonObject.class);
                        String accessToken = json.get("access_token").getAsString();
                        log.info("{}",accessToken);
                                
                        String userinfoUrl = "http://localhost:9000/userinfo";
                        HttpGet httpGet = new HttpGet(userinfoUrl);
                        httpGet.setHeader("Authorization",String.format("Bearer %s",accessToken));
                        httpGet.setHeader("Content-Type","application/json");
                        HttpEntity httpEntity = httpClient.execute(httpGet).getEntity();
                        String userInfo = EntityUtils.toString(httpEntity,StandardCharsets.UTF_8);
                        log.info("{}",userInfo);
                        return userInfo;
                    }
                }
                                
                """;
    }

    @Test
    @SneakyThrows
    @DisplayName("设备码模式")
    void testDeviceCode(){
        String clientId = "device-messaging-client";
        HttpClient httpClient = HttpClients.createDefault();
        HttpPost post = new HttpPost(AUTHORIZATION_URL+"/oauth2/device_authorization");
        post.setHeader("Content-Type", "application/x-www-form-urlencoded");
        List<NameValuePair> params = Lists.newLinkedList();
        params.add(new BasicNameValuePair("client_id",clientId));
        params.add(new BasicNameValuePair("scope","message.read"));
        post.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));
        HttpEntity entity = httpClient.execute(post).getEntity();
        String response = EntityUtils.toString(entity,Charsets.UTF_8);
        log.info(response);

        //再在浏览器输入
        //http://localhost:9000/activate
    }
}
