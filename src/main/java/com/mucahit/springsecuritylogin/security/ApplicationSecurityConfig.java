package com.mucahit.springsecuritylogin.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static com.mucahit.springsecuritylogin.security.ApplicationUserPermission.COURSE_WRITE;
import static com.mucahit.springsecuritylogin.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                /*.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())//cookie can not be accessible by client
                .and()*/
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())//permision based
                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())//permision based
                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())//permision based
                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())//role based
                .anyRequest()
                .authenticated()
                .and()
                //.httpBasic();
                .formLogin()
                .loginPage("/login").permitAll();
    }

    // instead of db , users are created in memory
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {

        UserDetails mucahitUser = User.builder()
                .username("mucahit")
                .password(passwordEncoder.encode("password"))
                //.roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails ahmetUser = User.builder()
                .username("ahmet")
                .password(passwordEncoder.encode("password"))
                //.roles(ADMIN.name()) //ROLE_ADMIN spring adds ROLE prefix automatically
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails mehmetUser = User.builder()
                .username("mehmet")
                .password(passwordEncoder.encode("password"))
                //.roles(ADMINTRAINEE.name()) //ROLE_ADMIN spring adds ROLE prefix automatically
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();
        return new InMemoryUserDetailsManager(
                mucahitUser, ahmetUser,mehmetUser);
    }

}
