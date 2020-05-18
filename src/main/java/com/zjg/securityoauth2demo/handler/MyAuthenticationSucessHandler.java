package com.zjg.securityoauth2demo.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Objects;

/**
 * @author zjg
 * @create 2020-03-16 11:22
 */
@Component
public class MyAuthenticationSucessHandler implements AuthenticationSuccessHandler {
    private final static Logger LOGGER = LoggerFactory.getLogger(MyAuthenticationSucessHandler.class);

    @Autowired
    private ClientDetailsService clientDetailsService;
    @Autowired
    private AuthorizationServerTokenServices authorizationServerTokenServices;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
                                        HttpServletResponse httpServletResponse,
                                        Authentication authentication)
            throws IOException, ServletException {
        //1，从请求头中获取 ClientId
        String header = httpServletRequest.getHeader("Authorization");
        if (Objects.isNull(header) || !header.startsWith("Basic ")) {
            throw new UnapprovedClientAuthenticationException("请求头中无 client 信息");
        }

        String[] tokens = this.extractAndDecodeHeader(header, httpServletRequest);
        String clientId = tokens[0];
        String clientSecret = tokens[1];

        TokenRequest tokenRequest = null;

        //2，通过 ClientDetailService 获取 ClientDetails
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);

        //3，校验 ClientId 和 ClientSecret 的正确性
        if (Objects.isNull(clientDetails)) {
            throw new UnapprovedClientAuthenticationException("clientId : " + clientId + " 对应的信息不存在");
        }else if (!passwordEncoder.matches(clientDetails.getClientSecret(), clientSecret)){
            throw new UnapprovedClientAuthenticationException("clientSecret不正确");
        }else {
            //4，通过 TokenRequest 构造器生成 TokenRequest
            tokenRequest = new TokenRequest(new HashMap<>(), clientId, clientDetails.getScope(), "custom");
        }

        //5，通过 TokenRequest 的 createOAuth2Request 方法获取 OAuth2Reqeust
        OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
        //6，通过 Authentication 和 OAuth2Request 构造出 OAuth2Authentication
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, authentication);

        //7，通过 AuthorizationServerTokenService 生成 OAuth2AccessToken
        OAuth2AccessToken token = authorizationServerTokenServices.createAccessToken(oAuth2Authentication);

        //8，返回 token
        LOGGER.info("登录成功");
        httpServletResponse.setContentType("application/json;charset=UTF-8");
        httpServletResponse.getWriter().write(objectMapper.writeValueAsString(token));
    }

    private String[] extractAndDecodeHeader(String header, HttpServletRequest request) {
        byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);

        byte[] decode;
        try {
            decode = Base64.getDecoder().decode(base64Token);
        }catch (IllegalArgumentException e) {
            throw new BadCredentialsException("Failed to decode basic authentication token");
        }

        String token = new String(decode, StandardCharsets.UTF_8);
        int delim = token.indexOf(":");
        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        } else {
            return new String[]{token.substring(0, delim), token.substring(delim+1)};
        }
    }


}
