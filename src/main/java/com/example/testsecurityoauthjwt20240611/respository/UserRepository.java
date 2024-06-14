package com.example.testsecurityoauthjwt20240611.respository;

import com.example.testsecurityoauthjwt20240611.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    UserEntity findByUsername(String username);
}
