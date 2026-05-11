package org.iths.springsecurityvg.Controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.iths.springsecurityvg.Model.AppUser;
import org.iths.springsecurityvg.Service.AppUserService;
import org.iths.springsecurityvg.Service.TotpService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
@RequestMapping("/2fa")
public class TwoFactorController {
    private final AppUserService appUserService;
    private final TotpService totpService;
    private final HttpSessionSecurityContextRepository securityContextRepository;

    public TwoFactorController(AppUserService appUserService, TotpService totpService, HttpSessionSecurityContextRepository securityContextRepository) {
        this.appUserService = appUserService;
        this.totpService = totpService;
        this.securityContextRepository = securityContextRepository;
    }

    @GetMapping
    public String showVerifyPage() {
        return "verify-2fa";
    }

    @PostMapping
    public String verifyTwoFactor(@RequestParam String code,
                                  HttpServletRequest req,
                                  HttpServletResponse res,
                                  Model model) {
        Authentication preAuth = SecurityContextHolder.getContext().getAuthentication();

        if (preAuth == null || !(preAuth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_PRE_AUTH")))) {
            return "redirect:/login";
        }

        String email = (String) preAuth.getPrincipal();

        AppUser user = appUserService.findUser(email).orElse(null);
        if (user == null) return "redirect:/login";

        if (!totpService.verifyCode(user.getTwoFactorSecret(), code)) {
            model.addAttribute("error", "Invalid code, try again");
            return "verify-2fa";
        }

        UsernamePasswordAuthenticationToken fullAuth = new UsernamePasswordAuthenticationToken(
                user.getEmail(),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole()))
        );

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(fullAuth);
        SecurityContextHolder.setContext(context);

        securityContextRepository.saveContext(context, req, res);

        return "redirect:/access";
    }
}
