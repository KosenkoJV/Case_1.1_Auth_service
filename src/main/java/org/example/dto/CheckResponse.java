// org/example/dto/CheckResponse.java
package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class CheckResponse {
    private boolean valid;
    private String subject;   // username
    private String role;
    private Long expiresAt;   // epoch millis
    private Long expiresIn;   // сек, может быть отрицательным если просрочен
    private String message;   // пояснение
}
