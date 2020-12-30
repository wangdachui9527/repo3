package cn.w2cl.springsecurity.springsecuritydemo.config;

import cn.w2cl.springsecurity.springsecuritydemo.handler.MyAccessDeniedHandler;
import cn.w2cl.springsecurity.springsecuritydemo.handler.MyAuthenticationFailureHandler;
import cn.w2cl.springsecurity.springsecuritydemo.handler.MyAuthenticationSuccessHandler;
import cn.w2cl.springsecurity.springsecuritydemo.service.UserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAccessDeniedHandler myAccessDeniedHandler;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private PersistentTokenRepository persistentTokenRepository;

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        //第一次启动true，第二次启动改为false
        //jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //关闭csrf 跨站请求伪造
        //http.csrf().disable();

        //表单提交
        http.formLogin()
                //自定义表单参数名
                .usernameParameter("username123")
                .passwordParameter("password123")
                //自定义登录页面
                .loginPage("/user/showLogin")
                //必须和表单提交的接口相同，就会去执行自定义登录逻辑，不需要在controller中有该方法
                .loginProcessingUrl("/login")
                //登陆成功后跳转的路径,只接受POST请求
                .successForwardUrl("/user/toMain")
                //自定义登陆成功处理器
                //.successHandler(new MyAuthenticationSuccessHandler("/main.html"))
                //.defaultSuccessUrl("/main.html");
                //登录失败跳转的路路径
                //.failureUrl("/error.html");
                .failureForwardUrl("/user/toError");
                //自定义登陆失败处理器
                //.failureHandler(new MyAuthenticationFailureHandler("/error.html"));


        //授权
        http.authorizeRequests()
                //放行指定的url /login.html ,不需要认证
                .antMatchers("/user/showLogin","/error.html").permitAll()
                //放行静态资源
                .antMatchers("/js/**", "/css/**", "/images/**").permitAll()
                //放行后缀.jpg
                //.antMatchers("/**/*.jpg").permitAll()
                //正则表达式 匹配放行
                //.regexMatchers(".+[.]jpg").permitAll()
                //指定请求方法 ，antMatchers也有
                //.regexMatchers(HttpMethod.POST,"/user/demo").permitAll()
                //.regexMatchers("/xxxx/user/demo").permitAll()
                //servletPath（当在配置文件中配置了全局的前缀 /xxxx 时可以使用这个，不过用的不多）
                //.mvcMatchers("/user/demo").servletPath("/xxxx").permitAll()
                //权限控制
                //基于权限
                //.antMatchers("/main1.html").hasAuthority("Admin")
                //.antMatchers("/main1.html").hasAnyAuthority("admin,admiN")
                //基于角色
                //.antMatchers("/main1.html").hasAnyRole("abc,abC")
                //.antMatchers("/main1.html").access("hasAnyRole('abc,abC')")
                //基于IP地址
                //.antMatchers("/main1.html").hasIpAddress("127.0.0.1")
                //所有的请求都必须认证才能访问，必须登录
                .anyRequest().authenticated();
                //自定义access方法
                //.anyRequest().access("@myServiceImpl.hasPermission(request,authentication)");
        //异常处理，自定义403权限不足页面
        http.exceptionHandling()
                .accessDeniedHandler(myAccessDeniedHandler);

        //记住我
        http.rememberMe()
                //设置数据源
                .tokenRepository(persistentTokenRepository)
                //对应表单的remember的checkbox的name
                .rememberMeParameter("rememberMe")
                //默认2周，设置60s 单位秒
                .tokenValiditySeconds(60)
                .userDetailsService(userDetailsService);

        //退出登录
        http.logout()
                //退出按钮的跳转，不用编写controller
                .logoutUrl("/logout")
                //退出成功后的页面
                .logoutSuccessUrl("/login.html");
    }
}
