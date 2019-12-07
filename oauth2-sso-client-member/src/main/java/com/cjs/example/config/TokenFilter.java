package com.cjs.example.config;

import com.cjs.example.dto.MyUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import org.springframework.beans.BeanUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.thymeleaf.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.*;

/**
 * create by： harry
 * date:  2019/12/7 0007 下午 10:17
 **/
@Component
public class TokenFilter extends BasicAuthenticationFilter {


    private final String  TOKEN_HEADER = "Authorization";
    private final String  TOKEN_PREFIX = "bearer";

    private ObjectMapper objectMapper;

    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public TokenFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        System.out.println("Bearer AuthenticationFilters");
        String tokenHeader = request.getHeader(TOKEN_HEADER);
        if(tokenHeader == null){
            tokenHeader = request.getParameter("bearer");
        }
        System.out.println("tokenHeader:"+tokenHeader);
        // 如果请求头中没有Authorization信息则直接放行了
        if (tokenHeader == null || ! StringUtils.equalsIgnoreCase(TOKEN_PREFIX, tokenHeader.substring(0, 6))) {
            chain.doFilter(request, response);
            return;
        }
        // 如果请求头中有token，则进行解析，并且设置认证信息
        Map map = new HashMap();
        UsernamePasswordAuthenticationToken authentication;
        response.setContentType("application/json;charset=utf-8");
        try{
            authentication = getAuthentication(tokenHeader);
            if(authentication == null){
                map.put("code", 400);
                map.put("msg", "无效的token凭据");
                response.getWriter().write(objectMapper.writeValueAsString(map));
                return;
            }
        }catch (ExpiredJwtException e){
            e.printStackTrace();
            map.put("code", 401);
            map.put("msg", "token已过期");
            response.getWriter().write(objectMapper.writeValueAsString(map));
            return;
        }catch (MalformedJwtException e){
            e.printStackTrace();
            map.put("code", 400);
            map.put("msg", "错误的token格式");
            response.getWriter().write(objectMapper.writeValueAsString(map));
            return;
        }catch (Exception e){
            e.printStackTrace();
            System.out.println("获取token错误");
            map.put("code", 403);
            map.put("msg", "获取用户信息失败");
            response.getWriter().write(objectMapper.writeValueAsString(map));
            return;
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        super.doFilterInternal(request, response, chain);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String tokenHeader) throws IOException {
        //解析Token时将“Bearer ”前缀去掉
        String token = StringUtils.substring(tokenHeader, 7);
        Claims claims = Jwts.parser()
                .setSigningKey("harry".getBytes("UTF-8"))
                .parseClaimsJws(token).getBody();
        List<GrantedAuthority> authorities = (List<GrantedAuthority>) claims.get("authorities");
        List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList("user:add");
        Map principle = (Map) claims.get("principle");
        String username = (String) principle.get("username");
        MyUser myUser = new MyUser(username, "null", grantedAuthorities);
        if (myUser.getUsername() != null){
            return new UsernamePasswordAuthenticationToken(myUser, null, grantedAuthorities);
        }
        return null;
    }
}
