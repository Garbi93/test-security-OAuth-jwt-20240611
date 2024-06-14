package com.example.testsecurityoauthjwt20240611.jwt;

import com.example.testsecurityoauthjwt20240611.dto.CustomOAuth2User;
import com.example.testsecurityoauthjwt20240611.dto.UserDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    // jwt Filter 를 사용하기 위해서 jwtUtil 내에 있는 검증 방식을 사용하려 하기 때문에 주입 받는다.
    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // cookie 들을 불러온 뒤 Authorization key 에 담긴 쿠키를 찾음
        String authorization = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("Authorization")) {
                authorization = cookie.getValue();
            }
        }

        // Authorization 헤더 검증
        if (authorization == null) {
            System.out.println("token null");
            filterChain.doFilter(request, response);

            // 비어있는 조건이라면 메소드 종료 (필수)
            return;
        }

        // authorization 값이 존재한다면 ?? 토큰에 authorization 값 저장하기
        String token = authorization;

        // 토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) {
            System.out.println("token expired");
            filterChain.doFilter(request, response);

            // 토큰 시간이 만료된 것 이라면 메소드 종료 (필수)
            return;
        }

        // 안전한 토큰 이라면 username 과 role 값을 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // 획득한 username 과 role 값을 userDTO 객체를 생성하여 값을 set
        UserDTO userDTO = new UserDTO();
        userDTO.setUsername(username);
        userDTO.setRole(role);

        // UserDetails 에 set 한 회원 정보 객체 담기
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);

        // 스프링 시큐리티 인증 토큰 생성 후 그 안에 UserDetails 정보를 담아 준다.
        Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());
        // 세션에 사용자 등록 -> 이 세션은 등록후 사라짐 stateLess 로 관리하기 때문에
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
