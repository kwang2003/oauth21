package com.example.oauth21.jose;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author Joe Grandja
 * @since 1.1
 */
final class KeyGeneratorUtils {

    private KeyGeneratorUtils() {
    }

    static SecretKey generateSecretKey() {
        SecretKey hmacKey;
        try {
            hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return hmacKey;
    }

    static KeyPair generateRsaKey() {
        String publicKeyPEM = """
                -----BEGIN PUBLIC KEY-----
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyomTkklXDwc3tV2r5Fnh
                VN6Hzy5/v7dBSlNV9nt5opsLxBJa4NFx12OaiyKq2eM58ulBh5UkM5LorywuAkcO
                emKppLBQ6I/JhG4UcbrP3z59T5PpTeokKhnW2YW7a9A7LPTXWMSOJXi2tl6WQJv+
                V/1z15euYzriv49/FFVvjhf9wlZmXziRjfPQAc4y5moDMycSp8p9tgScy49EnmiD
                FPqu3twjuij6TtYlG1h5b75567XN7BXEN9J5VA6zBkH/iBloXLpKdiQO4bK7KT1f
                xkAvbfNg1rEA1H7zBeBq93gyTJmG9eX9ITHzklVi6yulZFXzD1oU6N0VyzxYrDIn
                VQIDAQAB
                -----END PUBLIC KEY-----
                """;
        String privateKeyPEM = """
                -----BEGIN RSA PRIVATE KEY-----
                MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDKiZOSSVcPBze1
                XavkWeFU3ofPLn+/t0FKU1X2e3mimwvEElrg0XHXY5qLIqrZ4zny6UGHlSQzkuiv
                LC4CRw56YqmksFDoj8mEbhRxus/fPn1Pk+lN6iQqGdbZhbtr0Dss9NdYxI4leLa2
                XpZAm/5X/XPXl65jOuK/j38UVW+OF/3CVmZfOJGN89ABzjLmagMzJxKnyn22BJzL
                j0SeaIMU+q7e3CO6KPpO1iUbWHlvvnnrtc3sFcQ30nlUDrMGQf+IGWhcukp2JA7h
                srspPV/GQC9t82DWsQDUfvMF4Gr3eDJMmYb15f0hMfOSVWLrK6VkVfMPWhTo3RXL
                PFisMidVAgMBAAECggEAcpifB8E5YgZqbdL/RCfax+NVIlOj8nykk4JNfDXm36ss
                YBcmllfLOtxff+PwmXHowtlZu3YWUpwHzb2Ilr9PoM2cQNOGI9/fXG/QX30cyqqX
                ymPdOLmHFs8h8lepcNoT8V7jTZWA/BCuCMfB6fKZWX3NgqmPARQ7Ybm2ZHHmuZU1
                PsGzR5kSarGv+Hvg+bQ4ykqPLTGSisv+mNviSgxGDSK1sdrtiAl5L+rxLAM4ZegH
                O3FyZxFPiRX21bWsp1BrOSVe2/apLk7rAmgrxhCeAqLKnTt7JrHany8wucoPiNh0
                Bpi1VLnk8MG9L6Nr+LVCW13SIluAIqpmh+KDKMiELQKBgQDzY0vFx1XZ7hq2RPi7
                KOktqD5UW5oZzGxevXioQYNmo1yPMwAyhI0XHmKnsWBImhxIrMpz0n4UC4EcUAYx
                ZwRUl5Z7sOy3ovCWNdSVI07tPiHx7PcFhnhTHfkfGQ6cO4oj0RbWJbKAA8PFJ1LU
                uHkMGYqnvDzYA/VjCNrDWFIuZwKBgQDVCF8b4uSdoFSh9JcMGVfdEjUfsr1ow2fy
                k6VhZd94UuBt1RIQvUTH1Wxu/8W/rGFg5ICexMDvKufvlfZcUiOBaMH/ZFTMIHX6
                /gPQf0iorS+fT1U7z2Hu+zXD2KQmhEH5JHgbjpJuohib6qn/AyD7uOiY8WLvbqx4
                HAigok+u4wKBgDl4YeUCq6f5DD+ry5vODjlkt8sNkjazSYeZb8szJQbwXiPGJC7J
                k9M4rozwWk7qbPFQM8Hjmze6e7Mmxj+WFrSu0q7EWTEHfY3KijbpDnMAr91DWhTo
                6rKdqjyImyWS/Yx1i9HnNt35hZmhLnLiWFreERqIXUmYrbHD3nwv97/TAoGAM8tr
                RF5v8xsOOKo9J0XqJOfOXryYbKZF2aaoKPwZzylnQ4zwbX13AZcUXBB3xdhlfKdR
                1khEGGI4LfoqAdw+obIUqMF+FHs39CRaTREFW21wDK2/LWGIkBAnzEwZ7PtvBuIl
                CZ4qYBetIAt39XaPSGR2uOjHgytHZ5R5TITqFr0CgYEApgVuaP2+qhbltsOprLsF
                b4RnimH3F7mMwx8GiMN3OBcQ3+8bQbD4QnPMuhiEhJN07tazafrcrfBR0nWVDZ+2
                pBU1cRKukTsmPq8kzXdWP+MyU/4cebNCrCs30aVj7llipqn+LvZ5UOcbbKYD6457
                tSosU9y1GXsCjUyi8USAxvg=
                -----END RSA PRIVATE KEY-----
                """;
        PublicKey publicKey = getPublicKeyFromPEM(publicKeyPEM);
        PrivateKey privateKey = getPrivateKeyFromPEM(privateKeyPEM);

        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        return keyPair;
    }

    private static PublicKey getPublicKeyFromPEM(String publicKeyPEM) {
        try {
            String publicKeyString = publicKeyPEM
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static PrivateKey getPrivateKeyFromPEM(String privateKeyPEM) {
        try {
            String privateKeyString = privateKeyPEM
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }
}