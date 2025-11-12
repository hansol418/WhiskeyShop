package com.busanit501.boot501.config;

import com.busanit501.boot501.security.CustomUserDetailsService;
import com.busanit501.boot501.security.APIUserDetailsService;
import com.busanit501.boot501.security.handler.Custom403Handler;
import com.busanit501.boot501.security.handler.CustomSocialLoginSuccessHandler;
import com.busanit501.boot501.security.filter.APILoginFilter;
import com.busanit501.boot501.security.filter.TokenCheckFilter;
import com.busanit501.boot501.security.filter.RefreshTokenFilter;
import com.busanit501.boot501.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import javax.sql.DataSource;

@Log4j2
@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
@EnableWebSecurity
public class CustomSecurityConfig {

    private final DataSource dataSource;
    private final CustomUserDetailsService customUserDetailsService;
    // ip 에서 분당 요청 횟수 제한
    private final RateLimitingFilter rateLimitingFilter;

    // 추가 의존성 (JWT 관련)
    private final JWTUtil jwtUtil;
    private final APIUserDetailsService apiUserDetailsService;

    // 평문 패스워드를 해시 함수 이용해서 인코딩 해주는 도구 주입.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // AuthenticationManager 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    /* ============================
     * @Order(1) - API 체인 (/api/**)
     * - Stateless + JWT 필터
     * ============================ */
    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http,
                                                      AuthenticationManager authenticationManager) throws Exception {

        log.info("JWT 기반 API Security 설정 시작...");

        // API 로그인 필터 설정
        APILoginFilter apiLoginFilter = new APILoginFilter("/api/login");
        apiLoginFilter.setAuthenticationManager(authenticationManager);
        apiLoginFilter.setAuthenticationSuccessHandler(new com.busanit501.boot501.security.handler.APILoginSuccessHandler(jwtUtil, passwordEncoder()));

        http
                .securityMatcher("/api/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // 공개 API
                        .requestMatchers("/api/login", "/api/refresh").permitAll()
                        // 나머지 API는 인증 필요
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    /* ============================
     * @Order(2) - WEB 체인 (그 외)
     * - 세션 기반 폼 로그인 + OAuth2 + remember-me
     * ============================ */
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {

        log.info("시큐리티 동작 확인 ==== WebSecurityFilterChain ====");

        // 로그인 관련
        http.formLogin(formLogin -> formLogin
                .loginPage("/member/login").permitAll()
                // 🔧 정적 HTML 폼 사용을 위한 로그인 처리 URL & 파라미터명 매핑
                .loginProcessingUrl("/login")
                .usernameParameter("mid")
                .passwordParameter("mpw")
                .defaultSuccessUrl("/board/list", true) // 로그인 후, 성공시 리다이렉트

        );

        // 로그 아웃 설정
        http.logout(logout -> logout
                .logoutUrl("/member/logout")
                .logoutSuccessUrl("/member/login?logout")
        );

        // 기본은 csrf on, 작업시에는 끄고 작업하기.
        http.csrf(csrf -> csrf.disable());

        // 권한 설정 (WEB)
        http.authorizeHttpRequests(auth -> auth
                // 정적 자원 모두 허용
                .requestMatchers("/css/**", "/js/**", "/images/**", "/images2/**").permitAll()
                // 🔧 정적 HTML 경로 허용(Thymeleaf 미사용)
                .requestMatchers("/member/login.html", "/member/join.html", "/member/update.html").permitAll()
                // 리스트 등 공개 경로
                .requestMatchers("/", "/board/list", "/member/join", "/login", "/member/login",
                        "/joinUser", "/joinForm", "/findAll", "/images/**", "/members/**", "/item/**").permitAll()
                // 로그인 후 접근 필요
                .requestMatchers("/board/register", "/board/read", "/board/update").authenticated()
                // 관리자만
                .requestMatchers("/admin/**").hasRole("ADMIN")
                // 개발 단계: 나머지 요청 모두 허용
                .anyRequest().permitAll()
        );

        // 403 핸들러 적용
        http.exceptionHandling(ex -> ex.accessDeniedHandler(accessDeniedHandler()));

        // remember-me 설정
        http.rememberMe(remember -> remember
                .key("12345678")
                .tokenRepository(persistentTokenRepository())
                .userDetailsService(customUserDetailsService)
                .tokenValiditySeconds(60 * 60 * 24 * 30)
        );

        // 카카오 로그인(OAuth2) 설정
        http.oauth2Login(oauth -> oauth
                .loginPage("/member/login")
                .successHandler(authenticationSuccessHandler())
        );

        // 동일 아이피에서 분당 요청 횟수 10회 제한 , 필터 설정.
        http.addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // 소셜 로그인 후, 후처리 하는 빈등록.
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new CustomSocialLoginSuccessHandler(passwordEncoder());
    }

    // 자동로그인 설정 2 - 시스템에서 정의해둔 기본 약속.
    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
        repo.setDataSource(dataSource);
        return repo;
    }

    // 정적 자원 시큐리티 필터 항목에 제외하기.
    @Bean
    public org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer webSecurityCustomizer() {
        log.info("시큐리티 동작 확인 ====webSecurityCustomizer====");
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    // 사용자 정의한 403 예외 처리
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new Custom403Handler();
    }
}
