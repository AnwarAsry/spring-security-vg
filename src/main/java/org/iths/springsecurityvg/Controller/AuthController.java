package org.iths.springsecurityvg.Controller;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.iths.springsecurityvg.DTO.RegisterDTO;
import org.iths.springsecurityvg.Model.AppUser;
import org.iths.springsecurityvg.Service.AppUserService;
import org.iths.springsecurityvg.Service.TotpService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AuthController {

    private final AppUserService appUserService;
    private final TotpService totpService;

    public AuthController(AppUserService appUserService, TotpService totpService) {
        this.appUserService = appUserService;
        this.totpService = totpService;
    }

    @GetMapping("/login")
    public String showLoginPage() {
        return "login";
    }

    @GetMapping("/register")
    public String showRegister(Model model) {
        model.addAttribute("registerDTO", new RegisterDTO());
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute RegisterDTO dto,
                           BindingResult result,
                           HttpSession session, Model model) {

        if (result.hasErrors()) return "register";

        AppUser user = appUserService.registerUser(dto);

        if (user.isTwoFactorEnabled()) {
            try {
                String qrCode = totpService.generateQRCode(user.getEmail(), user.getTwoFactorSecret());
                session.setAttribute("2fa_setup_email", user.getEmail());
                model.addAttribute("qrCode", qrCode);
                return "setup-2fa";
            } catch (Exception e) {
                model.addAttribute("error", "Something went wrong setting up 2FA. Please try again.");
                return "register";
            }
        }

        return "redirect:/login";
    }
}
