package com.busanit501.boot501.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


@Component
@Log4j2
public class JWTUtil {


    @Value("${com.busanit501lsy.jwt.secret}")
    private String key;

    //  JJWT 0.11.x: byte[] 대신 Key 객체 사용 (비밀키는 최소 32바이트 권장)
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(key.getBytes());
    }

    public String generateToken(Map<String, Object> valueMap, int days){

        log.info("lsy generateKey..." + key);

        Map<String, Object> headers = new HashMap<>();
        headers.put("typ","JWT");
        headers.put("alg","HS256");

        Map<String, Object> payloads = new HashMap<>();
        payloads.putAll(valueMap);

        int time = (60 * 24) * days;

        String jwtStr = Jwts.builder()
                .setHeader(headers) // 기존 헤더 구성 유지
                .setClaims(payloads)
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant()))
                //  JJWT 0.11.x 방식
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();

        return jwtStr;
    }


    public Map<String, Object> validateToken(String token)throws JwtException {

        Map<String, Object> claim = null;

        //  JJWT 0.11.x: parserBuilder() 사용
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        claim = new HashMap<>(claims);
        return claim;
    }

}
