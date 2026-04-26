package org.iths.springsecurityvg;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.iths.springsecurityvg.Model.AppUser;
import org.iths.springsecurityvg.Service.AppUserService;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomSuccessHandler implements AuthenticationSuccessHandler {

    private final AppUserService appUserService;

    public CustomSuccessHandler(AppUserService appUserService) {
        this.appUserService = appUserService;
    }

    @Override
    public void onAuthenticationSuccess(@NonNull HttpServletRequest req, @NonNull HttpServletResponse res, Authentication auth) throws IOException {
        String email = auth.getName();

        AppUser user = appUserService.findUser(email).orElseThrow();

        if (user.isTwoFactorEnabled()) {
            SecurityContextHolder.clearContext();
            req.getSession().setAttribute("2fa_pending_email", email);
            res.sendRedirect("/twofa");
        } else {
            res.sendRedirect("/");
        }
    }
}
