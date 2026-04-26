package org.iths.springsecurityvg.Controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.iths.springsecurityvg.Model.AppUser;
import org.iths.springsecurityvg.Service.AppUserService;
import org.iths.springsecurityvg.Service.TotpService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/2fa")
public class TwoFactorController {
    private final AppUserService appUserService;
    private final TotpService totpService;

    public TwoFactorController(AppUserService appUserService, TotpService totpService) {
        this.appUserService = appUserService;
        this.totpService = totpService;
    }

    @GetMapping
    public String showVerifyPage() {
        return "verify-2fa";
    }

    @PostMapping
    public String verifyTwoFactor(@RequestParam String code,
                                  HttpSession session,
                                  HttpServletRequest req,
                                  HttpServletResponse res,
                                  Model model) {
        String email = (String) session.getAttribute("2fa_pending_email");
        if (email == null) return "redirect:/login";

        AppUser user = appUserService.findUser(email).orElse(null);
        if (user == null) return "redirect:/login";

        if (totpService.verifyCode(user.getTwoFactorSecret(), code)) {
            model.addAttribute("error", "Invalid code, try again");
            return "verify-2fa";
        }

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user.getEmail(), null);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);
        new HttpSessionSecurityContextRepository().saveContext(context, req, res);
        session.removeAttribute("2fa_pending_email");

        return "redirect:/";
    }
}
