package org.example.service;

import org.example.dto.*;
import org.example.entity.*;
import org.example.repository.*;
import lombok.RequiredArgsConstructor;
import org.example.security.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepo;
    private final TokenRepository tokenRepo;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public AuthResponse register(RegisterRequest req) {
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
        return issueTokens(user);
    }


    public AuthResponse login(LoginRequest req) {
        User user = userRepo.findByUsername(req.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        // Отзываем все старые refresh токены пользователя
        revokeAllUserRefreshTokens(user);

        return issueTokens(user);
    }

    public AuthResponse refresh(String refreshToken) {
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

        return new AuthResponse(newAccess, newRefresh);
    }

    public void logout(String refreshToken) {
        tokenRepo.findByToken(refreshToken).ifPresent(t -> {
            t.setRevoked(true);
            tokenRepo.save(t);
        });
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
}
