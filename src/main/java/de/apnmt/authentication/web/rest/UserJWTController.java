package de.apnmt.authentication.web.rest;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.apnmt.authentication.security.SecurityUtils;
import de.apnmt.authentication.security.jwt.JWTFilter;
import de.apnmt.authentication.security.jwt.TokenProvider;
import de.apnmt.authentication.web.rest.vm.LoginVM;
import de.apnmt.common.ApnmtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import javax.validation.Valid;
import java.util.Optional;

/**
 * Controller to authenticate users.
 */
@RestController
@RequestMapping("/api")
public class UserJWTController {

    private final Logger log = LoggerFactory.getLogger(UserJWTController.class);

    private final TokenProvider tokenProvider;

    private final ReactiveAuthenticationManager authenticationManager;

    public UserJWTController(TokenProvider tokenProvider, ReactiveAuthenticationManager authenticationManager) {
        this.tokenProvider = tokenProvider;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/authenticate")
    public Mono<ResponseEntity<JWTToken>> authorize(@Valid @RequestBody Mono<LoginVM> loginVM) {
        return loginVM
            .flatMap(login ->
                this.authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()))
                    .flatMap(auth -> Mono.fromCallable(() -> this.tokenProvider.createToken(auth, login.isRememberMe())))
            )
            .map(jwt -> {
                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.add(JWTFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
                return new ResponseEntity<>(new JWTToken(jwt), httpHeaders, HttpStatus.OK);
            });
    }

    @RequestMapping(path = "/authenticate/**", method = {RequestMethod.POST, RequestMethod.PUT, RequestMethod.GET, RequestMethod.DELETE, RequestMethod.PATCH})
    public Mono<ResponseEntity<String>> authenticate() {
        return SecurityUtils.getCurrentUserLogin().map(username -> ResponseEntity.ok().header(ApnmtUtil.USERNAME_HEADER, username).body("Authentication Successful")).defaultIfEmpty(ResponseEntity.ok().body("Authentication Successful"));
    }

    /**
     * Object to return as body in JWT Authentication.
     */
    static class JWTToken {

        private String idToken;

        JWTToken(String idToken) {
            this.idToken = idToken;
        }

        @JsonProperty("id_token")
        String getIdToken() {
            return this.idToken;
        }

        void setIdToken(String idToken) {
            this.idToken = idToken;
        }
    }
}
