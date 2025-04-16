package com.moayo.moayoeats.backend.global.jwt;

import static com.moayo.moayoeats.backend.global.jwt.JwtUtil.REFRESH_TOKEN_TIME;

import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class TokenRedisService {

    private final RedisTemplate<String, String> redisTemplate;

    // refresh token 저장
    public void saveRefreshToken(String email, String refreshToken) {

        redisTemplate.opsForValue()
            .set(email, refreshToken, REFRESH_TOKEN_TIME, TimeUnit.MILLISECONDS);
    }

    // refresh token 조회
    public String getRefreshToken(String email) {

        return redisTemplate.opsForValue().get(email);
    }

    // refresh token 삭제
    public void deleteRefreshToken(String email) {

        redisTemplate.opsForValue().getAndDelete(email);
    }

    // access token 블랙리스트 추가
    public void setBlacklist(String accessToken, String message, Long expiration) {

        redisTemplate.opsForValue().set(accessToken, message, expiration, TimeUnit.MILLISECONDS);
    }

    // 해당 access token이 블랙리스트에 있는지 확인
    public boolean isBlacklisted(String accessToken) {

        return redisTemplate.hasKey(accessToken);
    }
}
