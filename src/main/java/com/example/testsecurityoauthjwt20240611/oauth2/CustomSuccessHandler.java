package com.example.testsecurityoauthjwt20240611.oauth2;

import com.example.testsecurityoauthjwt20240611.dto.CustomOAuth2User;
import com.example.testsecurityoauthjwt20240611.jwt.JWTUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;

    public CustomSuccessHandler(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        // OAuth2User
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        String token = jwtUtil.createJwt(username, role, 60 * 60 * 60L);

        response.addCookie(createCookie("Authorization", token)); // 쿠키 만들기
        response.sendRedirect("http://localhost:3000/"); // 프론트로 생성한 쿠키 전달하기

    }

    // 쿠키를 만드는 메서드
    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(60 * 60 * 60); // 쿠키가 살아있을 시간
        // cookie.setSecure(true); // https 환경에서만 동작 하도록 하는 설정
        cookie.setPath("/"); // 모든 경로에서 cookie 인식 시키도록 하는 설정
        cookie.setHttpOnly(true); // js 에서 cookie 를 가져가지 못하도록 하는 설정

        return cookie;
    }

}
