package cn.springboot.security.demo01.service;


import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;


@Component
public class UserDetailsServiceImpl implements UserDetailsService {


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username == null || "".equals(username)) {
            throw new RuntimeException("用户不能为空");
        }
        /*//隐藏超级管理员特殊逻辑
        if(StringUtils.equals(AccountConstant.HIDE_SUPER_ADMIN,username)){
            List<SimpleGrantedAuthority> grantedAuthorities = new ArrayList<>();
            grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_LEINAO_ADMIN"));
            grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_MIDDLE"));
            grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            return new User(AccountConstant.HIDE_SUPER_ADMIN, new BCryptPasswordEncoder().encode(AccountConstant.HIDE_SUPER_ADMIN_PASSWORD), true,
                    true, true,
                    true,grantedAuthorities);
        }else{
            //根据用户名查询用户
            SysUser sysUser = sysUserService.selectByName(username);
            if (sysUser == null) {
                throw new RuntimeException("用户不存在");
            }
            List<SimpleGrantedAuthority> grantedAuthorities = new ArrayList<>();
            List<SysRole> roles = sysUser.getSysRoles();
            if (roles != null) {
                for (SysRole role : roles) {
                    grantedAuthorities.add(new SimpleGrantedAuthority(role.getRoleCode()));
                    List<SysPermission> sysPermissions = role.getSysPermissions();
                    if (sysPermissions != null) {
                        for (SysPermission permission : sysPermissions) {
                            grantedAuthorities.add(new SimpleGrantedAuthority(permission.getPermissionCode()));
                        }
                    }
                }
            }
            return new User(sysUser.getAccount(), sysUser.getPassword(), sysUser.getEnabled(),
                    sysUser.getAccountNonExpired(), sysUser.getCredentialsNonExpired(),
                    sysUser.getAccountNonLocked(),grantedAuthorities);
        }*/

        /**
         * 在此添加数据库验证逻辑
         */
        List<SimpleGrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_LEINAO_ADMIN"));
        grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_MIDDLE"));
        grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        return new User("SUPER_ADMIN", new BCryptPasswordEncoder().encode("123456"), true,
                true, true,
                true,grantedAuthorities);
    }
}
