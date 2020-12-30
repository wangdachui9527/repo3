package cn.w2cl.springsecurity.springsecuritydemo.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/user")
public class UserController {

    //@Secured("ROLE_abc")
    @PreAuthorize("hasRole('ROLE_abc')") //该注解是可以以ROLE_开头的，配置类是不允许的！
    @RequestMapping("/toMain")
    public String main(){
        return "redirect:main.html";
    }

    @RequestMapping("/toError")
    public String error(){
        return "redirect:error.html";
    }

    /**
     * 页面跳转
     * @return
     */
    @GetMapping("/demo")
    public String demo(){
        return "demo";
    }

    /**
     * 页面跳转
     * @return
     */
    @GetMapping("/showLogin")
    public String showLogin(){
        return "login";
    }
}
