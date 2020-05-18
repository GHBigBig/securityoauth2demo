package com.zjg.securityoauth2demo.web.controller;

import com.zjg.securityoauth2demo.beans.SmsCode;
import com.zjg.securityoauth2demo.service.RedisCodeService;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author zjg
 * @create 2020-03-17 10:14
 */
@RestController
public class ValidateController {
    @Autowired
    private RedisCodeService redisCodeService;

    @GetMapping("/code/sms")
    public void createSmsCode(HttpServletRequest request,
                              HttpServletResponse response,
                              String mobile)
            throws Exception {
        SmsCode smsCode = createSMSCode();
        redisCodeService.save(smsCode, new ServletWebRequest(request), mobile);
        //输出验证码到控制台代替短信发送服务
        System.out.println("手机号：" + mobile + " 的登录验证码为：" + smsCode.getCode() + "，有效时间为 300 秒");
    }

    private SmsCode createSMSCode() {
        String code = RandomStringUtils.randomNumeric(6);
        return new SmsCode(code);
    }
}