package com.zjg.securityoauth2demo.conf;

import com.zjg.securityoauth2demo.enhancer.JWTTokenEnhancer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * @author zjg
 * @create 2020-03-18 17:18
 */
@Configuration
public class JWTTokenConfig {
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new JWTTokenEnhancer();
    }

    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
        accessTokenConverter.setSigningKey("test_key"); // 签名密钥
        return accessTokenConverter;
    }

}
