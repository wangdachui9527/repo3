package cn.w2cl.springsecurity.springsecuritydemo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //根据用户名去数据库查询,如果不存在 抛异常 UsernameNotFoundException
        if(!"admin".equals(username)){
            throw new UsernameNotFoundException("用户名不存在");
        }
        //比较密码(注册时要加密过) 如果匹配就返回UserDetails,
        String password = passwordEncoder.encode("123"); //实际是从数据库查询出的

        return new User(username,password, AuthorityUtils.commaSeparatedStringToAuthorityList("admin,normal,ROLE_abc,/main.html,/insert,/delete"));
    }
}
