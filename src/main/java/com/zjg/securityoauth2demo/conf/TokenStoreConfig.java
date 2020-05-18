package com.zjg.securityoauth2demo.conf;

import jdk.nashorn.internal.parser.Token;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

/**
 * 默认令牌是存储在内存中的，我们可以将它保存到第三方存储中，比如Redis。
 * 然后在认证服务器里指定该令牌存储策略。
 * 重写configure(AuthorizationServerEndpointsConfigurer endpoints)方法：
 *
 * @author zjg
 * @create 2020-03-18 17:05
 */
//@Configuration
//@EnableAuthorizationServer
public class TokenStoreConfig {
    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    @Bean
    public TokenStore redisTokentore() {
        return new RedisTokenStore(redisConnectionFactory);
    }
}
