package com.example.testsecurityoauthjwt20240611.service;

import com.example.testsecurityoauthjwt20240611.dto.*;
import com.example.testsecurityoauthjwt20240611.entity.UserEntity;
import com.example.testsecurityoauthjwt20240611.respository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    // DB 에 접근 해야하기 때문에 필요한 기능이 있는 Repository를 의존성 주입 받아야한다.
    private final UserRepository userRepository;


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

        // OAuth2 로그인 로직
        // naver 나 goole 이 제공해준 고유 ID 값으로 우리 서비스에서 사용할 ID 로 만들어주기
        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();

        // 우리 DB 에 넣어주거나 DB 에 이미 존재할 경우의 로직
        UserEntity existData = userRepository.findByUsername(username);

        if (existData == null) {
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setEmail(oAuth2Response.getEmail());
            userEntity.setName(oAuth2Response.getName());
            userEntity.setRole("ROLE_USER");

            // DB 에 저장하기
            userRepository.save(userEntity);

            // 회원 정보를 담을 바구니 객체 만들기
            UserDTO userDTO = new UserDTO();
            // 바구니 객체에 로그인할 회원 정보 넣어주기
            userDTO.setUsername(username);
            userDTO.setName(oAuth2Response.getName());
            userDTO.setRole("ROLE_USER");
            // 로그인 진행
            return new CustomOAuth2User(userDTO);
        } else {
            existData.setEmail(oAuth2Response.getEmail());
            existData.setName(oAuth2Response.getName());

            userRepository.save(existData);

            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(existData.getUsername());
            userDTO.setName(oAuth2Response.getName());
            userDTO.setRole(existData.getRole());

            return new CustomOAuth2User(userDTO);
        }


    }
}
