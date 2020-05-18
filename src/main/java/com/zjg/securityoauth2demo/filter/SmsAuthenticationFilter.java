package com.zjg.securityoauth2demo.filter;

import com.zjg.securityoauth2demo.token.SmsAuthenticationToken;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * SmsAuthenticationFilter的过滤器来拦截短信验证码登录请求，
 * 并将手机号码封装到一个叫SmsAuthenticationToken的对象中
 *
 * @author zjg
 * @create 2020-03-16 18:36
 */
public class SmsAuthenticationFilter  extends
        AbstractAuthenticationProcessingFilter {

    //    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";
    public static final String MOBILE_KEY = "mobile";

    //    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
    //mobileParameter属性值为mobile，对应登录页面手机号输入框的name属性。
    private String mobileParameter = MOBILE_KEY;
    private boolean postOnly = true;

    /**
     * 指定了当请求为/login/mobile，请求方法为POST的时候该过滤器生效。
     */
    public SmsAuthenticationFilter() {
        super(new AntPathRequestMatcher("/login/mobile", "POST"));
    }

    /**
     * 从请求中获取到mobile参数值，并调用SmsAuthenticationToken的
     * SmsAuthenticationToken(String mobile)构造方法创建了一个SmsAuthenticationToken。
     * SmsAuthenticationFilter将SmsAuthenticationToken交给AuthenticationManager处理。
     *
     *
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }

        String mobile = obtainMobile(request);

        if (mobile == null) {
            mobile = "";
        }

        mobile = mobile.trim();

        SmsAuthenticationToken authRequest = new SmsAuthenticationToken(mobile);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    @Nullable
    protected String obtainMobile(HttpServletRequest request) {
        return request.getParameter(mobileParameter);
    }

    protected void setDetails(HttpServletRequest request,
                              SmsAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    public void setMobileParameter(String mobileParameter) {
        Assert.hasText(mobileParameter, "Username parameter must not be empty or null");
        this.mobileParameter = mobileParameter;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public final String getMobileParameter() {
        return mobileParameter;
    }
}


