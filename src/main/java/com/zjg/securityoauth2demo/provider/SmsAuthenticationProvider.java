package com.zjg.securityoauth2demo.provider;

import com.zjg.securityoauth2demo.token.SmsAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * 用来给 AuthenticationManage 调用用来身份验证
 *
 * @author zjg
 * @create 2020-03-16 18:46
 */
public class SmsAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;

    /**
     * 编写具体的身份认证逻辑
     * 从SmsAuthenticationToken中取出了手机号信息，并调用了UserDetailService的loadUserByUsername方法。
     * 在短信验证码认证的过程中，该方法需要通过手机号去查询用户，如果存在该用户则认证通过。
     * 认证通过后接着调用
     * SmsAuthenticationToken的SmsAuthenticationToken(
     *      Object principal, Collection<? extends GrantedAuthority> authorities)
     * 构造函数构造一个认证通过的Token，包含了用户信息和用户权限。
     *
     *
     * @param authentication
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //从SmsAuthenticationToken中取出了手机号信息
        SmsAuthenticationToken authenticationToken = (SmsAuthenticationToken) authentication;
        UserDetails userDetails = userDetailsService.loadUserByUsername(
                (String) authenticationToken.getPrincipal());

        if (userDetails==null) {
            throw new InternalAuthenticationServiceException("此手机号未注册！");
        }

        //构造一个认证通过的Token，包含了用户信息和用户权限。
        SmsAuthenticationToken authenticationResult = new SmsAuthenticationToken(
                userDetails, userDetails.getAuthorities());
        authenticationResult.setDetails(authentication.getDetails());

        return authenticationResult;
    }

    /**
     * 指定了支持处理的Token类型为SmsAuthenticationToken
     *
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return SmsAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}

