package org.example.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
@Table(name = "tokens")
public class Token {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable=false, columnDefinition="TEXT")
    private String token;

    @Column(nullable=false)
    private String type; // ACCESS / REFRESH

    private boolean revoked;
}
