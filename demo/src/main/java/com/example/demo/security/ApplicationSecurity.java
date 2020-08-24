package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.demo.security.ApplicationUserPermission.*;
import static com.example.demo.security.ApplicationUserRole.*;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //for using @PreAuthorize into the controllers
public class ApplicationSecurity extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurity(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //X-XSRF-TOKEN
        http
                .csrf().disable()
                //.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())

                //.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                //.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                //.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                //.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())

                .anyRequest()
                .authenticated()
                .and()
                //.httpBasic();
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .defaultSuccessUrl("/courses", true)
                    //.passwordParameter("password") //default is password
                    //.usernameParameter("username") //default is username
                .and()
                .rememberMe()//default is 2 weeks
                            .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                            .key("somethingisverysecured")
                            //.rememberMeParameter("remember-me") //default is remember-me
                .and()
                .logout()
                    .logoutUrl("/logout")
                    //if csrf is enable logout method should be POST or get rid of this line
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID","remember-me")
                    .logoutSuccessUrl("/login");

    }

    @Bean
    protected UserDetailsService userDetailsService() {

        var jasimUser =User
                .builder()
                .username("jasim")
                .password(passwordEncoder.encode( "password"))
                //.roles(STUDENT.name())
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        var abdulla =User
                .builder()
                .username("abdulla")
                .password(passwordEncoder.encode( "password123"))
                .authorities(ADMIN.getGrantedAuthorities())
                //.roles(ADMIN.name())
                .build();

        var tom =User
                .builder()
                .username("tom")
                .password(passwordEncoder.encode( "password123"))
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                //.roles(ADMINTRAINEE.name())
                .build();

        return new InMemoryUserDetailsManager(
               jasimUser,abdulla, tom
        );
    }
}
