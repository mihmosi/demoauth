package com.jwt_auth.configs.jwt;

import com.jwt_auth.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;


    @Autowired
    private UserDetailsServiceImpl userDetailsService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
// Ф И Л Ь Т Р У Е М ЗАПРОС ================================
        try {
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) { //ЕСЛИ НЕ ПУСТОЙ И ВАЛИДНЫЙ
                String username = jwtUtils.getUserNameFromJwtToken(jwt); // ВЫТАСКИВАЕМ ИЗ ТОКЕНА USERNAME

                UserDetails userDetails = userDetailsService.loadUserByUsername(username); // ПЕРЕДАЕМ В userDetails
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken( // ПОЛУЧАЕМ ТОКЕН
                        userDetails, null, userDetails.getAuthorities());

                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authenticationToken); // В КОНТЕКСТ ПЕРЕДАЕМ ТОКЕН
            }

        } catch (Exception e) {
            System.err.println(e);
        }
        filterChain.doFilter(request, response); // РАЗРЕШАЕМ ПРОХОД ДАЛЬШЕ
    }

    //  ПРОВЕРЯЕМ В ХЕДЕРЕ ТОКЕН "Authorization"
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

// ПРОВЕРЯЕМ НАЧИНАЕТСЯ СО СЛОВА Bearer
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7, headerAuth.length());
        }

        return null;
    }
}
