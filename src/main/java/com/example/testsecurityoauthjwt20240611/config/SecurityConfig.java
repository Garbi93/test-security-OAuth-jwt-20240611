package com.example.testsecurityoauthjwt20240611.config;

import com.example.testsecurityoauthjwt20240611.jwt.JWTFilter;
import com.example.testsecurityoauthjwt20240611.jwt.JWTUtil;
import com.example.testsecurityoauthjwt20240611.oauth2.CustomSuccessHandler;
import com.example.testsecurityoauthjwt20240611.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService oAuth2UserService;

    private final CustomSuccessHandler customSuccessHandler;

    private final JWTUtil jwtUtil;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // csrf disable 처리
        http
                .csrf((csrf) -> csrf.disable());

        // FormLogin 방식 disable 처리
        http
                .formLogin((auth) -> auth.disable());

        // http basic 인증 방식 disable 처리
        http
                .httpBasic((auth) -> auth.disable());

        // JWTFilter 추가 하기 .addFilterBefore 은 특정 필터 이전에 작동하게 한다는 기능
        http
                .addFilterBefore(new JWTFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);


        // oauth2 로그인 관련 설정
        http
                .oauth2Login((oauth2)-> oauth2
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(oAuth2UserService))
                                .successHandler(customSuccessHandler) // CustomSuccessHandler 설정 추가
                );

        // 경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/").permitAll()
                        .anyRequest().authenticated());

        // 세션 설정 : stateLess 하게 변경
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));






        return http.build();
    }
}
