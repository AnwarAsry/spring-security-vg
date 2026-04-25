package org.iths.springsecurityvg.Service;

import org.iths.springsecurityvg.DTO.RegisterDTO;
import org.iths.springsecurityvg.Model.AppUser;
import org.iths.springsecurityvg.Repository.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AppUserService {
    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;

    public AppUserService(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public AppUser registerUser(RegisterDTO dto) {
        if (appUserRepository.findByEmail(dto.getEmail()).isPresent()) {
            throw new RuntimeException("User with this email already exists");
        }

        AppUser user = new AppUser();
        user.setEmail(dto.getEmail());
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        user.setTwoFactorEnabled(dto.isTwoFactorEnabled());

        // Code to set secret
//        if (dto.isTwoFactorEnabled()) {
//            user.setTwoFactorSecret();
//        }

        return appUserRepository.save(user);
    }

    public Optional<AppUser> findUser(String email) {
        return appUserRepository.findByEmail(email);
    }
}
