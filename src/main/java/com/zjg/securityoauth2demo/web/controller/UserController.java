package com.zjg.securityoauth2demo.web.controller;

import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;

/**
 * @author zjg
 * @create 2020-03-16 10:51
 */
@RestController
public class UserController {
    @GetMapping("/index")
    public Object index(@AuthenticationPrincipal Authentication authentication,
                        HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        String token = StringUtils.substringAfter(header, "bearer");
        return Jwts.parser()    //signkey需要和JwtAccessTokenConverter中指定的签名密钥一致
                .setSigningKey("test_key".getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token)
                .getBody();
    }
}
