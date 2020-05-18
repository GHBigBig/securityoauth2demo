package com.zjg.securityoauth2demo.service;

import com.zjg.securityoauth2demo.beans.SmsCode;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.concurrent.TimeUnit;

/**
 * Redis 操作码验证服务
 *
 * @author zjg
 * @create 2020-03-16 17:59
 */
@Service
public class RedisCodeService {
    private static final String SMS_CODE_PREFIX = "SMS_CODE:";
    private static final Integer TIME_OUT = 300;

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    /**
     * 保存验证码到 redis
     *
     * @param smsCode 短信验证码
     * @param request ServletWebRequest
     * @param mobile  手机号
     * @throws Exception
     */
    public void save(SmsCode smsCode, ServletWebRequest request, String mobile) throws Exception {
        stringRedisTemplate.opsForValue().set(key(request, mobile), smsCode.getCode(), TIME_OUT, TimeUnit.SECONDS);
    }

    /**
     * 获取验证码
     *
     * @param request
     * @param mobile
     * @return 验证码
     * @throws Exception
     */
    public String get(ServletWebRequest request, String mobile) throws Exception {
        return stringRedisTemplate.opsForValue().get(key(request, mobile));
    }

    /**
     * 移除验证码
     *
     * @param request
     * @param mobile
     * @throws Exception
     */
    public void remove(ServletWebRequest request, String mobile) throws Exception {
        stringRedisTemplate.delete(key(request, mobile));
    }

    private String key(ServletWebRequest request, String mobile) throws Exception {
        String deviceId = request.getHeader("deviceId");
        if (StringUtils.isBlank(deviceId)) {
            throw new Exception("请在请求头设置deviceId");
        }
        return SMS_CODE_PREFIX + deviceId + ":" + mobile;
    }

}
