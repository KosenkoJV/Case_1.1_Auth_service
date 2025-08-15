package org.example.service;

import jakarta.servlet.http.HttpServletResponse;
import org.example.Util.CookieUtil;
import org.example.dto.*;
import org.example.entity.*;
import org.example.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepo;
    private final TokenRepository tokenRepo;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final CookieUtil cookieUtil;

    public AuthResponse register(RegisterRequest req, HttpServletResponse response) {
        if (userRepo.findByUsername(req.getUsername()).isPresent()) {
            throw new RuntimeException("User already exists");
        }

        String role = req.getRole();
        if (role == null || role.isBlank()) {
            role = "USER"; // по умолчанию
        }
        User user = User.builder()
                .username(req.getUsername())
                .password(passwordEncoder.encode(req.getPassword()))
                .role(role)
                .build();
        userRepo.save(user);

        AuthResponse tokens = issueTokens(user);
        cookieUtil.addTokenCookies(response, tokens.getAccessToken(), tokens.getRefreshToken());
        return tokens;
    }


    public AuthResponse login(LoginRequest req, HttpServletResponse response) {
        User user = userRepo.findByUsername(req.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        // Отзываем все старые refresh токены пользователя
        revokeAllUserRefreshTokens(user);

        AuthResponse tokens = issueTokens(user);
        cookieUtil.addTokenCookies(response, tokens.getAccessToken(), tokens.getRefreshToken());
        return tokens;
    }

    public AuthResponse refresh(String refreshToken, HttpServletResponse response) {
        var parsed = jwtService.parseToken(refreshToken);
        if (parsed.getBody().getExpiration().before(new Date())) {
            throw new RuntimeException("Refresh token expired");
        }

        Token stored = tokenRepo.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        if (stored.isRevoked()) throw new RuntimeException("Token revoked");

        User user = stored.getUser();

        // Отзываем старый refresh токен
        stored.setRevoked(true);
        tokenRepo.save(stored);

        // Создаем новый refresh токен
        String newRefresh = jwtService.generateToken(user, "REFRESH");

        tokenRepo.save(Token.builder()
                .user(user)
                .token(newRefresh)
                .type("REFRESH")
                .revoked(false)
                .build());

        // Создаем новый access токен
        String newAccess = jwtService.generateToken(user, "ACCESS");

        cookieUtil.addTokenCookies(response, newAccess, newRefresh);

        return new AuthResponse(newAccess, newRefresh);
    }

    public String logout(String refreshToken, HttpServletResponse response) {
        tokenRepo.findByToken(refreshToken).ifPresent(t -> {
            t.setRevoked(true);
            tokenRepo.save(t);
        });

        // Удаляем куки
        ResponseCookie deleteAccess = ResponseCookie.from("access_token", "")
                .httpOnly(true)
                .path("/")
                .maxAge(0)
                .build();

        ResponseCookie deleteRefresh = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .path("/")
                .maxAge(0)
                .build();

        response.addHeader("Set-Cookie", deleteAccess.toString());
        response.addHeader("Set-Cookie", deleteRefresh.toString());

        return "Successfully logged out";
    }


    private AuthResponse issueTokens(User user) {
        String access = jwtService.generateToken(user, "ACCESS");
        String refresh = jwtService.generateToken(user, "REFRESH");

        // Сохраняем только refresh токен
        tokenRepo.save(Token.builder()
                .user(user)
                .token(refresh)
                .type("REFRESH")
                .revoked(false)
                .build());

        return new AuthResponse(access, refresh);
    }

    private void revokeAllUserRefreshTokens(User user) {
        var tokens = tokenRepo.findAllValidRefreshTokensByUser(user.getId());
        for (Token token : tokens) {
            token.setRevoked(true);
        }
        tokenRepo.saveAll(tokens);
    }

    public boolean isTokenValid(String token) {
        try {
            var claims = jwtService.parseToken(token);
            return claims.getBody().getExpiration().after(new Date());
        } catch (Exception e) {
            return false;
        }
    }
}
