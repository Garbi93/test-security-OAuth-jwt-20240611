package com.example.testsecurityoauthjwt20240611.config;

import com.example.testsecurityoauthjwt20240611.jwt.JWTFilter;
import com.example.testsecurityoauthjwt20240611.jwt.JWTUtil;
import com.example.testsecurityoauthjwt20240611.oauth2.CustomSuccessHandler;
import com.example.testsecurityoauthjwt20240611.service.CustomOAuth2UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService oAuth2UserService;

    private final CustomSuccessHandler customSuccessHandler;

    private final JWTUtil jwtUtil;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // cors 설정
        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000")); // 허용할 프론트 주소
                        configuration.setAllowedMethods(Collections.singletonList("*")); // get, post put 등 모든 요청에 대해 허용
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*")); // 모든 헤더 값 허용
                        configuration.setMaxAge(3600L);

                        // 백엔트가 프론트의 헤더에 반환할 쿠키
                        configuration.setExposedHeaders(Collections.singletonList("Set-Cookie"));
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                }));

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
                //.addFilterBefore(new JWTFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);
                // 만료토큰 로그인시 무한루프로 인해 코드 수정
                .addFilterAfter(new JWTFilter(jwtUtil), OAuth2LoginAuthenticationFilter.class);


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
