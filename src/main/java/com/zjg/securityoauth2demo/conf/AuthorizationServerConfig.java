package com.zjg.securityoauth2demo.conf;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.ArrayList;
import java.util.List;

/**
 * 在同时定义了认证服务器和资源服务器后，
 * 再去使用授权码模式获取令牌可能会遇到
 * Full authentication is required to access this resource
 * 的问题，这时候只要确保认证服务器先于资源服务器配置即可，
 * 比如在认证服务器的配置类上使用@Order(1)标注，
 * 在资源服务器的配置类上使用@Order(2)标注。
 * 我加上 @Order 后 401错误
 *
 * @author zjg
 * @create 2020-03-15 21:52
 */
//@Order(-1024)
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Qualifier("userDetailServiceImpl")
    @Autowired
    private UserDetailsService userDetailsService;
    //    @Autowired
//    private TokenStore redisTokenStore;
    @Autowired
    private TokenStore jwtTokenStore;
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;
    @Autowired
    private TokenEnhancer tokenEnhancer;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        /*endpoints.authenticationManager(authenticationManager)
//                .tokenStore(redisTokenStore);   //令牌存储到 redis 中
                .tokenStore(jwtTokenStore)
                .accessTokenConverter(jwtAccessTokenConverter)
                .userDetailsService(userDetailsService);*/
        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> enhancers = new ArrayList<>();
        enhancers.add(tokenEnhancer);
        enhancers.add(jwtAccessTokenConverter);
        enhancerChain.setTokenEnhancers(enhancers);

        endpoints.authenticationManager(authenticationManager)
                .tokenStore(jwtTokenStore)
                .accessTokenConverter(jwtAccessTokenConverter)
                .tokenEnhancer(enhancerChain)
                .userDetailsService(userDetailsService);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("test1")
                .secret(passwordEncoder().encode("test1111")) //指定client_secret的时候需要进行加密处理：
                .accessTokenValiditySeconds(3600)    //令牌有效时间为3600秒
                .refreshTokenValiditySeconds(864000) //有效时间为864000秒，即10天，
                .scopes("all", "a", "b", "c")   //cope只能指定为all，a，b或c中的某个值，否则将获取失败；
                .authorizedGrantTypes("password","refresh_token")
                .and()
                .withClient("test2")
                .secret(passwordEncoder().encode("test2222"))
                .accessTokenValiditySeconds(7200);   //令牌有效时间为7200秒

    }
}
