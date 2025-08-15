package org.example.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.example.dto.*;
import org.example.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest req, HttpServletResponse response) {
        return ResponseEntity.ok(authService.register(req, response));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest req, HttpServletResponse response) {
        return ResponseEntity.ok(authService.login(req, response));
    }

    @GetMapping("/check")
    public ResponseEntity<Map<String, Object>> check(@CookieValue(name="access_token", required=false) String token) {
        boolean valid = authService.isTokenValid(token);
        return ResponseEntity.ok(Map.of("valid", valid));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@CookieValue ("refresh_token")String refreshToken,
                                                HttpServletResponse response) {
        return ResponseEntity.ok(authService.refresh(refreshToken, response));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@CookieValue(name = "refresh_token", required = false) String refreshToken,
                                                      HttpServletResponse response) {
        if (refreshToken != null) {
            String message = authService.logout(refreshToken, response);
            return ResponseEntity.ok(Map.of("message", message));
        }
        return ResponseEntity.badRequest().body(Map.of("error", "No refresh token provided"));
    }
}
