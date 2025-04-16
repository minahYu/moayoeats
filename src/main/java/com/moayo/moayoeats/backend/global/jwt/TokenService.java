package com.moayo.moayoeats.backend.global.jwt;

import static com.moayo.moayoeats.backend.global.jwt.JwtUtil.AUTHORIZATION_HEADER;
import static com.moayo.moayoeats.backend.global.jwt.JwtUtil.REFRESH_TOKEN_HEADER;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@RequiredArgsConstructor
@Service
public class TokenService {

    private final TokenRedisService tokenRedisService;
    private final JwtUtil jwtUtil;

    public String relatedIssuanceOfTokens(
        HttpServletRequest req,
        HttpServletResponse res
    ) throws IOException {

        String accessToken = jwtUtil.getTokenFromRequest(req, AUTHORIZATION_HEADER);
        String refreshToken = jwtUtil.getTokenFromRequest(req, REFRESH_TOKEN_HEADER);

        if (StringUtils.hasText(accessToken) && StringUtils.hasText(refreshToken)) {
            accessToken = jwtUtil.substringToken(accessToken);
            refreshToken = jwtUtil.substringToken(refreshToken);

            accessTokenIsValid(accessToken, refreshToken, res);
            return accessTokenIsInvalid(accessToken, refreshToken, res);
        }
        return "";
    }

    private void accessTokenIsValid(
        String accessToken,
        String refreshToken,
        HttpServletResponse res
    ) throws IOException { // accessToken 유효할 경우

        if (jwtUtil.validateToken(accessToken)) {
            Claims info = jwtUtil.getUserInfoFromToken(refreshToken);
            try {
                if (info == null) {
                    info = jwtUtil.getUserInfoFromToken(accessToken);
                }
                String email = info.getSubject();
                if (tokenRedisService.getRefreshToken(email) == null) { // refreshToken 만료시
                    String newRefreshToken = jwtUtil.createRefreshToken(email); // refreshToken 생성
                    tokenRedisService.saveRefreshToken(email, newRefreshToken);
                    jwtUtil.addJwtToCookie(newRefreshToken, res, REFRESH_TOKEN_HEADER);
                }
            } catch (Exception e) {
                throw new RuntimeException("refresh token 생성 실패", e);
            }
        }
    }

    private String accessTokenIsInvalid(
        String accessToken,
        String refreshToken,
        HttpServletResponse res
    ) throws IOException { // accessToken 만료시

        if (!jwtUtil.validateToken(accessToken)) {
            if (jwtUtil.validateToken(refreshToken)) { // refreshToken 유효
                Claims info = jwtUtil.getUserInfoFromToken(refreshToken);
                String email = info.getSubject();
                String newAccessToken = jwtUtil.createToken(email);

                if (!newAccessToken.equals("")) {
                    jwtUtil.addJwtToCookie(newAccessToken, res, AUTHORIZATION_HEADER);
                    return newAccessToken;
                }
            }
            res.sendRedirect("/login"); // 두 토큰 모두 만료
        }
        return "";
    }
}
