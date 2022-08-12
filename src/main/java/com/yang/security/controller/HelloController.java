package com.yang.security.controller;

import com.yang.security.entity.SysUser;
import com.yang.security.security.LoginUserDetails;
import com.yang.security.utils.JwtUtil;
import com.yang.security.utils.RedisUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Objects;

@RestController
public class HelloController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private RedisUtil redisUtil;

    @GetMapping("/hi")
    public Object hi(String name) {
        return "hello " + name;
    }

    @PostMapping("/login")
    public Object login(@RequestBody SysUser sysUser) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(sysUser.getUsername(), sysUser.getPassword());

        try{
            // 认证
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 认证失败
            if(Objects.isNull(authentication)) {
                throw new RuntimeException("用户名或密码错误");
            }

            // 认证成功
            LoginUserDetails loginUserDetails = (LoginUserDetails) authentication.getPrincipal();
            String userid = String.valueOf(loginUserDetails.getSysUser().getId());

            // 根据用户id生成jwt, 将用户信息存入redis
            redisUtil.set("login:" + userid, loginUserDetails);

            return JwtUtil.createJWT(userid);
        }catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    @PostMapping("/logout2")
    public Object logout() {
        try {
            // 获取SecurityContextHolder中用户id
            UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
            LoginUserDetails loginUser = (LoginUserDetails) authentication.getPrincipal();
            // 删除redis中值
            redisUtil.del("login:"+loginUser.getSysUser().getId());
            return loginUser;
        }catch (Exception e) {
            return "未登录!";
        }
    }
}