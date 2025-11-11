package com.busanit501.boot501.security.filter;


import com.google.gson.Gson;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Map;

@Log4j2
public class APILoginFilter extends AbstractAuthenticationProcessingFilter {

    public APILoginFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        log.info("lsy APILoginFilter-----------------------------------");

        if (request.getMethod().equalsIgnoreCase("GET")) {
            log.info("GET METHOD NOT SUPPORT");
            return null;
        }
        log.info("-----------------------------------------");
        log.info("lsy request.getMethod()" + request.getMethod());

        Map<String, String> jsonData = parseRequestJSON(request);

        log.info("lsy jsonData: "+jsonData);

        if (jsonData == null) {
            throw new AuthenticationServiceException("Empty or invalid JSON");
        }

        // 🔧 1번 프로젝트 키(mid/mpw) 우선, 2번 호환(username/password)도 fallback
        String mid = jsonData.getOrDefault("mid", jsonData.get("username"));
        String mpw = jsonData.getOrDefault("mpw", jsonData.get("password"));

        if (mid == null || mpw == null) {
            throw new AuthenticationServiceException("Missing credentials (mid/mpw or username/password)");
        }

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(mid, mpw); // 🔧 principal=mid

        return getAuthenticationManager().authenticate(authenticationToken);
    }


    private Map<String,String> parseRequestJSON(HttpServletRequest request) {


        try(Reader reader = new InputStreamReader(request.getInputStream())){

            Gson gson = new Gson();

            return gson.fromJson(reader, Map.class);

        }catch(Exception e){
            log.error(e.getMessage());
        }
        return null;
    }
}
