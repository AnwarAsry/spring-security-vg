package org.iths.springsecurityvg.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.iths.springsecurityvg.Model.AppUser;
import org.iths.springsecurityvg.Service.AppUserService;
import org.iths.springsecurityvg.TwoFactorAuthority;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

@Component
public class CustomSuccessHandler implements AuthenticationSuccessHandler {

    private final AppUserService appUserService;
    private final HttpSessionSecurityContextRepository securityContextRepository;

    public CustomSuccessHandler(AppUserService appUserService, HttpSessionSecurityContextRepository securityContextRepository) {
        this.appUserService = appUserService;
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    public void onAuthenticationSuccess(@NonNull HttpServletRequest req, @NonNull HttpServletResponse res, Authentication auth) throws IOException {
        String email = auth.getName();

        AppUser user = appUserService.findUser(email).orElseThrow();

        if (user.isTwoFactorEnabled()) {
            UsernamePasswordAuthenticationToken preAuth = new UsernamePasswordAuthenticationToken(
                    email,
                    null,
                    List.of(new TwoFactorAuthority())
            );

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(preAuth);
            SecurityContextHolder.setContext(context);
            securityContextRepository.saveContext(context, req, res);

            res.sendRedirect("/2fa");
        } else {
            res.sendRedirect("/access");
        }
    }
}
