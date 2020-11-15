package cn.springboot.security.demo01.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/product")
public class ProductTestController {

    @RequestMapping("/info")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    public String productInfo(){
        String currentUserName;
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if(principal instanceof UserDetails){
            currentUserName = ((UserDetails) principal).getUsername();
        }else{
            currentUserName = principal.toString();
        }
        return " some product info " + currentUserName;
    }
}
