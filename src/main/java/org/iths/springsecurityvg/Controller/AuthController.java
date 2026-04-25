package org.iths.springsecurityvg.Controller;

import jakarta.validation.Valid;
import org.iths.springsecurityvg.DTO.RegisterDTO;
import org.iths.springsecurityvg.Model.AppUser;
import org.iths.springsecurityvg.Service.AppUserService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AuthController {

    private final AppUserService appUserService;

    public AuthController(AppUserService appUserService) {
        this.appUserService = appUserService;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String showRegister(Model model) {
        model.addAttribute("registerDTO", new RegisterDTO());
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute RegisterDTO dto,
                           Model model) {

        AppUser user = appUserService.registerUser(dto);

        if (user.isTwoFactorEnabled()) {
            // Make QR Code
        }

        return "redirect:/auth/login";
    }
}
