package com.jwt_auth.configs.jwt;

import com.jwt_auth.service.UserDetailsImpl;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {
    // ВВОДИМ ПЕРЕМЕННЫЕ
    @Value("${app.jwtSecret}")
    private String jwtSecret;
    @Value("${app.jwtExpirationMs}")
    private int jwtExpirationMs;

    // ГЕНЕРИРУЕМ ТОКЕН ДЛЯ ОТДАЧИ КЛИЕНТУ
    public String generateJwtToken(Authentication authentication) {
        // ПРИНИМАЕМ ЮЗЕРА ДЛЯ ПОДТВЕРЖДЕНИЯ
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
// СОЗДАЕМ ГОТОТВЫЙ ТОКЕН С ИМЕНЕМ, ТЕЛОМ И ПОПИСЬЮ И ==== ШИФРУЕМ
        return Jwts.builder().setSubject((userPrincipal.getUsername())).setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret).compact();
    }


    // В ОТВЕТ НА ЗАПРОС С КЛИЕНТА ПРОВЕРЯЕМ И ПОДТВЕРЖДАЕМ ПОДЛИННОСТЬ
    public boolean validateJwtToken(String jwt) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(jwt);
            return true;  // ЕСЛИ ВАЛИДНЫЙ
        } catch (MalformedJwtException | IllegalArgumentException e) {
            System.err.println(e.getMessage());
        }
        return false;
    }

    public String getUserNameFromJwtToken(String jwt) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(jwt).getBody().getSubject();
    }
}
