package com.example.oauth21.config;

import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class RsaConfig {
    @Value("${oauth2.token.sign.rsa.public-key}")
    private String publicKey;
    @Value("${oauth2.token.sign.rsa.private-key}")
    private String privateKey;

    @Bean
    public KeyPair rsaKeyPair() {
        PublicKey publicKey = getPublicKeyFromPEM(this.publicKey);
        PrivateKey privateKey = getPrivateKeyFromPEM(this.privateKey);
        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        return keyPair;
    }

    @SneakyThrows
    private PublicKey getPublicKeyFromPEM(String publicKeyPEM) {
        String publicKeyString = publicKeyPEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    @SneakyThrows
    private PrivateKey getPrivateKeyFromPEM(String privateKeyPEM) {
        String privateKeyString = privateKeyPEM
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}
