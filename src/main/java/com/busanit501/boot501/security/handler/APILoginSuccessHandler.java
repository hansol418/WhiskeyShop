package com.busanit501.boot501.security.handler;



import com.busanit501.boot501.security.dto.MemberSecurityDTO;
import com.busanit501.boot501.util.JWTUtil;
import com.google.gson.Gson;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class APILoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        log.info("lsy Login Success Handler................................");

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        log.info("lsy authentication : " +authentication);
        log.info("lsy authentication.getName() : " +authentication.getName());

        Map<String, Object> claim = Map.of("username", authentication.getName());

        String accessToken = jwtUtil.generateToken(claim, 1);

        String refreshToken = jwtUtil.generateToken(claim, 30);

        Gson gson = new Gson();

        Map<String,String> keyMap = Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken,
                "username", authentication.getName());

        String jsonStr = gson.toJson(keyMap);

        response.getWriter().println(jsonStr);

        log.info("=====CustomSocialLoginSuccessHandler  onAuthenticationSuccess 확인 ===============================");
        log.info(authentication.getPrincipal());

        MemberSecurityDTO memberSecurityDTO = (MemberSecurityDTO) authentication.getPrincipal();
        String encodePw = memberSecurityDTO.getPassword();
        log.info("패스워드를 변경해주세요. encodePw = memberSecurityDTO.getPassword(); : " + encodePw);

        boolean test1 = memberSecurityDTO.getPassword().equals("1111");
        boolean test2 = passwordEncoder.matches("1111", memberSecurityDTO.getPassword());
        log.info("패스워드 일치 여부1 memberSecurityDTO.getMpw().equals(\"1111\"); : " + test1);
        log.info("패스워드 일치 여부2  passwordEncoder.matches(\"1111\", memberSecurityDTO.getMpw()); : " + test2);


        if( memberSecurityDTO.isSocial()
                && memberSecurityDTO.getPassword().equals("1111") || passwordEncoder.matches("1111", memberSecurityDTO.getPassword())){
            log.info("패스워드를 변경해주세요.");
            log.info("회원 정보 변경하는 페이지로 리다이렉트, 마이 페이지가 없음. 일단 수동으로 임의로 변경하기 ");
            log.info(("memberSecurityDTO 확인: " + memberSecurityDTO));
            boolean test3 = memberSecurityDTO.getPassword().equals("1111");
            boolean test4 = passwordEncoder.matches("1111", memberSecurityDTO.getPassword());
            log.info("패스워드 일치 여부3 memberSecurityDTO.getMpw().equals(\"1111\"); : " + test3);
            log.info("패스워드 일치 여부4  passwordEncoder.matches(\"1111\", memberSecurityDTO.getMpw()); : " + test4);
            response.sendRedirect("/main");
        }

    }
}