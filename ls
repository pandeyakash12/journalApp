[1mdiff --git a/src/main/java/net/engineeringdigest/journalApp/config/SpringSecurity.java b/src/main/java/net/engineeringdigest/journalApp/config/SpringSecurity.java[m
[1mindex 69fdc8c..8a507a4 100644[m
[1m--- a/src/main/java/net/engineeringdigest/journalApp/config/SpringSecurity.java[m
[1m+++ b/src/main/java/net/engineeringdigest/journalApp/config/SpringSecurity.java[m
[36m@@ -1,40 +1,40 @@[m
[31m-[m
 package net.engineeringdigest.journalApp.config;[m
 [m
[31m-import io.jsonwebtoken.Jwt;[m
[31m-import net.engineeringdigest.journalApp.filter.JwtFilter;[m
 import net.engineeringdigest.journalApp.service.UserDetailsServiceImpl;[m
 import org.springframework.beans.factory.annotation.Autowired;[m
 import org.springframework.context.annotation.Bean;[m
 import org.springframework.context.annotation.Configuration;[m
[31m-import org.springframework.security.authentication.AuthenticationManager;[m
[32m+[m[32mimport org.springframework.context.annotation.Profile;[m
[32m+[m[32mimport org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;[m
 import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;[m
 import org.springframework.security.config.annotation.web.builders.HttpSecurity;[m
 import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;[m
 import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;[m
 import org.springframework.security.config.http.SessionCreationPolicy;[m
[32m+[m[32mimport org.springframework.security.core.userdetails.UserDetailsService;[m
 import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;[m
 import org.springframework.security.crypto.password.PasswordEncoder;[m
[31m-import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;[m
 [m
 @Configuration[m
 @EnableWebSecurity[m
[31m-public class SpringSecurity extends WebSecurityConfigurerAdapter {[m
[32m+[m[32m@Profile("dev")[m
[32m+[m[32mpublic class SpringSecurity extends WebSecurityConfigurerAdapter[m
[32m+[m[32m{[m
 [m
     @Autowired[m
     private UserDetailsServiceImpl userDetailsService;[m
 [m
[31m-    @Autowired[m
[31m-    private JwtFilter jwtFilter;[m
[31m-[m
     @Override[m
[31m-    protected void configure(HttpSecurity http) throws Exception {[m
[32m+[m[32m    protected void configure(HttpSecurity http) throws Exception[m
[32m+[m[32m    {[m
         http.authorizeRequests()[m
                 .antMatchers("/journal/**", "/user/**").authenticated()[m
                 .antMatchers("/admin/**").hasRole("ADMIN")[m
[31m-                .anyRequest().permitAll();[m
[32m+[m[32m                .anyRequest().permitAll()[m
[32m+[m[32m                .and()[m
[32m+[m[32m                .httpBasic();[m
[32m+[m[32m        http.csrf().disable();[m
         http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().csrf().disable();[m
[31m-        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);[m
     }[m
 [m
     @Override[m
[36m@@ -46,10 +46,4 @@[m [mpublic class SpringSecurity extends WebSecurityConfigurerAdapter {[m
     public PasswordEncoder passwordEncoder() {[m
         return new BCryptPasswordEncoder();[m
     }[m
[31m-[m
[31m-    @Bean[m
[31m-    @Override[m
[31m-    public AuthenticationManager authenticationManagerBean() throws Exception {[m
[31m-        return super.authenticationManagerBean();[m
[31m-    }[m
[31m-}[m
[32m+[m[32m}[m
\ No newline at end of file[m
[1mdiff --git a/src/main/java/net/engineeringdigest/journalApp/constant/Placeholders.java b/src/main/java/net/engineeringdigest/journalApp/constant/Placeholders.java[m
[1mindex 761cfdf..b3769ff 100644[m
[1m--- a/src/main/java/net/engineeringdigest/journalApp/constant/Placeholders.java[m
[1m+++ b/src/main/java/net/engineeringdigest/journalApp/constant/Placeholders.java[m
[36m@@ -1,4 +1,4 @@[m
[31m-package net.engineeringdigest.journalApp.constants;[m
[32m+[m[32mpackage net.engineeringdigest.journalApp.constant;[m
 [m
 public interface Placeholders {[m
     String API_KEY = "<apiKey>";[m
