package org.iths.springsecurityvg;

import org.springframework.security.core.GrantedAuthority;

public class TwoFactorAuthority implements GrantedAuthority {

    @Override
    public String getAuthority() {
        return "ROLE_PRE_AUTH";
    }
}
