package com.zjg.securityoauth2demo.filter;

import com.zjg.securityoauth2demo.service.RedisCodeService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Spring Security实际上是由许多过滤器组成的过滤器链，
 * 处理手机登录逻辑的过滤器为 SmsAuthenticationFilter
 * 而短信验证码校验过程应该是在这个过滤器之前的，
 * 即只有短信验证码校验通过后才去读取用户信息
 * 由于Spring Security并没有直接提供短信验证码校验相关的过滤器接口，
 * 所以我们需要自己定义一个验证码校验的过滤器SmsCodeFilter
 * <p>
 * 我们实现了通过短信验证码登录系统的功能，
 * 通过短信验证码获取令牌和它唯一的区别就是验证码的存储策略。
 * 之前的例子验证码存储在Session中，
 * 现在使用令牌的方式和系统交互后Session已经不适用了，
 * 我们可以使用第三方存储来保存我们的验证码（无论是短信验证码还是图形验证码都是一个道理），
 * 比如Redis等。
 *
 * @author zjg
 * @create 2020-03-16 18:19
 */
@Component
public class SmsCodeFilter extends OncePerRequestFilter {

    @Autowired
    private RedisCodeService redisCodeService;

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;


    /**
     * ValidateCodeFilter继承了org.springframework.web.filter.OncePerRequestFilter，该过滤器只会执行一次
     * <p>
     * 在doFilterInternal方法中我们判断了请求URL是否为/login，
     * 该路径对应登录form表单的action路径，请求的方法是否为POST，
     * 是的话进行验证码校验逻辑，否则直接执行filterChain.doFilter让代码往下走。
     * 当在验证码校验的过程中捕获到异常时，
     * 调用Spring Security的校验失败处理器AuthenticationFailureHandler进行处理。
     *
     * @param httpServletRequest
     * @param httpServletResponse
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse, FilterChain filterChain)
            throws ServletException, IOException {

        if (StringUtils.equalsIgnoreCase("/login/mobile", httpServletRequest.getRequestURI())
                && StringUtils.equalsIgnoreCase("post", httpServletRequest.getMethod())) {
            try {
                validateCode(new ServletWebRequest(httpServletRequest));
            } catch (Exception e) {
                authenticationFailureHandler.onAuthenticationFailure(httpServletRequest, httpServletResponse,
                        new AuthenticationServiceException(e.getMessage()));
                return;
            }
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    /**
     * Session中获取了SmsCode对象和请求参数smsCode（对应登录页面的验证码<input>框name属性）,
     * 然后进行了各种判断并抛出相应的异常。当验证码过期或者验证码校验通过时，
     * 我们便可以删除Session中的SmsCode属性了。
     * <p>
     * 先应从 redis 中获取
     *
     * @param servletWebRequest
     * @throws ServletRequestBindingException
     */
    private void validateCode(ServletWebRequest servletWebRequest) throws Exception {
        String codeInRequest = ServletRequestUtils.getStringParameter(servletWebRequest.getRequest(), "smsCode");
        String mobileInRequest = ServletRequestUtils.getStringParameter(servletWebRequest.getRequest(), "mobile");

        String codeInRedis = redisCodeService.get(servletWebRequest, mobileInRequest);

        if (StringUtils.isBlank(codeInRequest)) {
            throw new Exception("验证码不为空！");
        }

        if (codeInRedis == null) {
            throw new Exception("验证码已过期，请重新发送！");
        }
        if (!StringUtils.equalsIgnoreCase(codeInRedis, codeInRequest)) {
            throw new Exception("验证码错误！");
        }

        redisCodeService.remove(servletWebRequest, mobileInRequest);
    }
}
