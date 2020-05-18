package com.zjg.securityoauth2demo.beans;

import java.io.Serializable;

/**
 * @author zjg
 * @create 2020-03-16 18:14
 */
public class SmsCode implements Serializable {
    private static final long serialVersionUID = -3958498367238394063L;
    private String code;

    public SmsCode(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
