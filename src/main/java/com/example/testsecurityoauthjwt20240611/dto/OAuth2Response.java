package com.example.testsecurityoauthjwt20240611.dto;

public interface OAuth2Response {
    // 어쩐 제공자 인지
    String getProvider();

    // 제공자에서 발급해주는 아이디 (고유번호)
    String getProviderId();

    // 회원 이메일
    String getEmail();

    // 사용자 실명 (OR 닉네임)
    String getName();
}
