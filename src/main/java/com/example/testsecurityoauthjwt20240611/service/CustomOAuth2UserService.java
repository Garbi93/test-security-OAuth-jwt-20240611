package com.example.testsecurityoauthjwt20240611.service;

import com.example.testsecurityoauthjwt20240611.dto.GoogleResponse;
import com.example.testsecurityoauthjwt20240611.dto.NaverResponse;
import com.example.testsecurityoauthjwt20240611.dto.OAuth2Response;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        System.out.println(oAuth2User);

        // 이 OAuth2 서비스가 naver 인지 google 인지 확인을 위한 String 값을 받자
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // naver, google 을 모두 담을 수 있는 타입의 바구니 만들기
        OAuth2Response oAuth2Response = null;

        if (registrationId.equals("naver")) {
            //바구니에 naver 담기
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        } else if (registrationId.equals("google")) {
            // 바구니에 google 담기
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        } else {
            return null;
        }

        // 로그인 완료 후 로직 
    }
}
