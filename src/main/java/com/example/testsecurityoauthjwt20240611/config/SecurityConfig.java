package com.example.testsecurityoauthjwt20240611.config;

import com.example.testsecurityoauthjwt20240611.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService oAuth2UserService;

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

        // oauth2 로그인 관련 설정
        http
                .oauth2Login((oauth2)-> oauth2
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(oAuth2UserService)));

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
