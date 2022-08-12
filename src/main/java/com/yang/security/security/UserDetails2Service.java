package com.yang.security.security;

import com.yang.security.entity.SysUser;
import com.yang.security.mapper.SysUserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class UserDetails2Service implements UserDetailsService {

    @Autowired
    private SysUserMapper sysUserMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SysUser user = sysUserMapper.queryByUsername(username);
        if(user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }

        // 因为数据库是明文，所以这里需加密密码
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return new LoginUserDetails(user);
    }
}
