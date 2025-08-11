package org.example.repository;


import org.example.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByToken(String token);
    @Query("SELECT t FROM Token t WHERE t.user.id = :userId AND t.type = 'REFRESH' AND t.revoked = false")
    List<Token> findAllValidRefreshTokensByUser(Long userId);
}
