package org.iths.springsecurityvg.Model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    private boolean twoFactorEnabled = false;

    private String twoFactorSecret;

    public AppUser(String email, String password, boolean twoFactorEnabled, String twoFactorSecret) {
        this.email = email;
        this.password = password;
        this.twoFactorEnabled = twoFactorEnabled;
        this.twoFactorSecret = twoFactorSecret;
    }
}