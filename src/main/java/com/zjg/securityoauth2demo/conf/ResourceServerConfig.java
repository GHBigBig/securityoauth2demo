package com.zjg.securityoauth2demo.conf;

import com.zjg.securityoauth2demo.filter.SmsCodeFilter;
import com.zjg.securityoauth2demo.handler.MyAuthenticationFailureHandler;
import com.zjg.securityoauth2demo.handler.MyAuthenticationSucessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
 * @create 2020-03-16 10:58
 */
//@Order(1024)
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    @Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;
    @Autowired
    private MyAuthenticationFailureHandler autenticationFailureHandler;
    @Autowired
    private SmsCodeFilter smsCodeFilter;
    @Autowired
    private SmsAuthenticationConfig smsAuthenticationConfig;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(smsCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加短信验证码校验过滤器
                .formLogin()    // 表单登录
                .loginProcessingUrl("/login")   // 处理表单登录 URL
                .successHandler(authenticationSucessHandler)    // 处理登录成功
                .failureHandler(autenticationFailureHandler)    // 处理登录失败
                .and()
                .authorizeRequests()    // 授权配置
                .antMatchers("/code/sms")
                .permitAll()
                .anyRequest()   // 所有请求
                .authenticated()     // 都需要认证
                .and()
                .csrf()
                .disable()
                .apply(smsAuthenticationConfig);    //短信验证码登录过程
    }
}
