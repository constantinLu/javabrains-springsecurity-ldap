package com.springtutorial.springsecurityldap;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;

@EnableWebSecurity
public class SpringConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       auth
               .ldapAuthentication()
               .userDnPatterns("uid={0},ou=people")  // Dn = distinguish name (see ou in ldap-data. dn.)
               .groupSearchBase("ou=groups") // organizationUnit is groups.
               .contextSource()
               .url("ldap://localhost:8389/dc=springframework,dc=org") // the url where ldap server is hosted
               .and()
               .passwordCompare()
               .passwordEncoder(new LdapShaPasswordEncoder())
               .passwordAttribute("userPassword"); //the user password (stored in ldap pass).


    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().fullyAuthenticated()
                .and()
                .formLogin();
    }
}
