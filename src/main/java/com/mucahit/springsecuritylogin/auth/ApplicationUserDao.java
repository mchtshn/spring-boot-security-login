package com.mucahit.springsecuritylogin.auth;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser> findApplicationUserByUsername(String username);
}
