package org.iths.springsecurityvg.DTO;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterDTO {
    @Email
    @NotBlank
    private String email;

    @NotBlank
    @Size(min = 2, max = 20)
    private String password;

    private boolean twoFactorEnabled;
}
