package cn.springboot.security.demo01.config;

import cn.springboot.security.demo01.filter.JwtAuthenticationFilter;
import cn.springboot.security.demo01.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").roles("ADMIN", "USER").password("$2a$10$pEhgeiR6AVsROTi0z6g6.ObwsIqQkf77hnIBejv2u.DJs78o/VjJ2") //密码是123456
                .and()
                .withUser("lisi").roles("USER").password("$2a$10$pEhgeiR6AVsROTi0z6g6.ObwsIqQkf77hnIBejv2u.DJs78o/VjJ2");
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authenticationProvider(authenticationProvider()).httpBasic().
                /*and()
                .exceptionHandling().authenticationEntryPoint(new AuthenticationEntryPoint(){
                    *//**
                     * 匿名用户访问无权限资源时的异常
                     * @param httpServletRequest
                     *//*
                    @Override
                    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        httpServletResponse.setContentType("text/json;charset=utf-8");
                        httpServletResponse.getWriter().write("用户未登录");
                    }
                }).*/
                and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//禁用session,是无状态的，并没有登录状态保持，服务器通过客户端调用传递的token来识别调用者是谁
                .and()
                .authorizeRequests()  //定义哪些URL需要被保护、哪些不需要被保护
//                    .antMatchers("/product/**").hasRole("USER") //这里定义USER角色可以访问
//                    .antMatchers("/admin/**").hasRole("ADMIN") //这里定义ADMIN角色可以访问
                    .antMatchers("/getLogs/**").permitAll() //这里不用登陆也可以访问，即允许匿名访问
                    .anyRequest().authenticated()  //其他请求必须授权
                .and()
                .formLogin() //定义当需要用户登录时候，转到的登录页面。此时，我们并没有写登录页面，但是spring security默认提供了一个登录页面，以及登录控制器。
                .permitAll()
                .failureHandler(new AuthenticationFailureHandler(){
                    //处理登陆失败
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        if (e instanceof AccountExpiredException) {
                            //账号过期
                        } else if (e instanceof BadCredentialsException) {
                            //密码错误
                        } else if (e instanceof CredentialsExpiredException) {
                            //密码过期
                        } else if (e instanceof DisabledException) {
                            //账号不可用
                        } else if (e instanceof LockedException) {
                            //账号锁定
                        } else if (e instanceof InternalAuthenticationServiceException) {
                            //用户不存在
                        } else {
                            //其他错误
                        }
                        httpServletResponse.setContentType("text/json;charset=utf-8");
                        httpServletResponse.getWriter().write("登陆失败");
                    }
                })
                .successHandler(new AuthenticationSuccessHandler(){
                    //登录成功处理逻辑
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        //可以加密生成token返回给前端，下次前端带上token即可
                        /*String jwt = jwtTokenUtil.createJWT(expiration, userDetails.getUsername(), secret);
                        SysUser sysUser = sysUserService.selectByName(userDetails.getUsername());
                        sysUser.setAccount(userDetails.getUsername());
                        sysUser.setUserName(userDetails.getUsername());
                        sysUser.setToken(jwt);
                        //返回json数据
                        JsonResult result = ResultTool.success(sysUser);
                        httpServletResponse.setHeader(tokenHeader,tokenPrefix+" "+jwt);
                        httpServletResponse.setContentType("text/json;charset=utf-8");
                        httpServletResponse.getWriter().write(JSON.toJSONString(result));*/
                    }
                })
                .and()
                .exceptionHandling()//没有权限，返回json
                .accessDeniedHandler(new AccessDeniedHandler(){
                    @Override
                    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
                        httpServletResponse.setContentType("application/json;charset=utf-8");
                        httpServletResponse.getWriter().write("没有权限");
                    }
                })
                .and()
                .logout()
                //退出成功，返回json
                .logoutSuccessHandler(new LogoutSuccessHandler(){
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.setContentType("text/json;charset=utf-8");
                        httpServletResponse.getWriter().write("退出成功");
                    }
                })
                .permitAll();
        //开启跨域访问
        http.cors();
        //开启模拟请求，比如API POST测试工具的测试，不开启时，API POST为报403错误
        http.csrf().disable();
        //添加过滤器，对token进行校验
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        //对默认的UserDetailsService进行覆盖
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        //自定义用户验证类，从数据库获取用户名和密码来验证，并设置用户权限
        return new UserDetailsServiceImpl();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        /**
         * Spring Security 中提供了 BCryptPasswordEncoder 密码编码工具，
         * 可以非常方便的实现密码的加密加盐，相同明文加密出来的结果总是不同，这样就不需要用户去额外保存盐的字段了，这一点比 Shiro 要方便很多。
         * BCryptPasswordEncoder使用哈希算法+随机盐来对字符串加密。因为哈希是一种不可逆算法，所以密码认证时需要使用相同的算法+盐值来对待校验的明文进行加密，
         * 然后比较这两个密文来进行验证。BCryptPasswordEncoder在加密时通过从传入的salt中获取real_salt用来加密，保证了这一点。
         */
        return new BCryptPasswordEncoder();
    }

}
