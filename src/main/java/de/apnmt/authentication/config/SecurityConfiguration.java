package de.apnmt.authentication.config;

import de.apnmt.authentication.security.AuthoritiesConstants;
import de.apnmt.authentication.security.jwt.JWTFilter;
import de.apnmt.authentication.security.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.zalando.problem.spring.webflux.advice.security.SecurityProblemSupport;
import tech.jhipster.config.JHipsterProperties;

import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Import(SecurityProblemSupport.class)
public class SecurityConfiguration {

    private final JHipsterProperties jHipsterProperties;

    private final ReactiveUserDetailsService userDetailsService;

    private final TokenProvider tokenProvider;

    private final SecurityProblemSupport problemSupport;

    public SecurityConfiguration(
        ReactiveUserDetailsService userDetailsService,
        TokenProvider tokenProvider,
        JHipsterProperties jHipsterProperties,
        SecurityProblemSupport problemSupport
    ) {
        this.userDetailsService = userDetailsService;
        this.tokenProvider = tokenProvider;
        this.jHipsterProperties = jHipsterProperties;
        this.problemSupport = problemSupport;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        UserDetailsRepositoryReactiveAuthenticationManager authenticationManager = new UserDetailsRepositoryReactiveAuthenticationManager(
            this.userDetailsService
        );
        authenticationManager.setPasswordEncoder(passwordEncoder());
        return authenticationManager;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        // @formatter:off
        http
            .securityMatcher(new NegatedServerWebExchangeMatcher(new OrServerWebExchangeMatcher(
                pathMatchers("/app/**", "/i18n/**", "/content/**", "/swagger-ui/**", "/swagger-resources/**", "/v2/api-docs", "/v3/api-docs", "/test/**"),
                pathMatchers(HttpMethod.OPTIONS, "/**")
            )))
            .csrf()
            .disable()
            .addFilterAt(new JWTFilter(this.tokenProvider), SecurityWebFiltersOrder.HTTP_BASIC)
            .authenticationManager(reactiveAuthenticationManager())
            .exceptionHandling()
            .accessDeniedHandler(this.problemSupport)
            .authenticationEntryPoint(this.problemSupport)
            .and()
            .headers()
            .contentSecurityPolicy(this.jHipsterProperties.getSecurity().getContentSecurityPolicy())
            .and()
            .referrerPolicy(ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
            .and()
            .permissionsPolicy().policy("camera=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), sync-xhr=()")
            .and()
            .frameOptions().disable()
            .and()
            .authorizeExchange()
            .pathMatchers("/api/authenticate").permitAll()

            // Authentication for Backend Services
            // AppointmentService
            .pathMatchers(HttpMethod.POST, "/api/authenticate/service/appointment/api/appointments").permitAll()
            .pathMatchers(HttpMethod.PUT, "/api/authenticate/service/appointment/api/appointments/**").permitAll()
            .pathMatchers(HttpMethod.DELETE, "/api/authenticate/service/appointment/api/appointments/**").permitAll()
            .pathMatchers(HttpMethod.GET, "/api/authenticate/service/appointment/api/appointments/{id}").permitAll()
            .pathMatchers(HttpMethod.GET, "/api/authenticate/service/appointment/api/appointments/organization/**").authenticated()
            .pathMatchers(HttpMethod.GET, "/api/authenticate/service/appointment/api/appointments").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers(HttpMethod.GET, "/api/authenticate/service/appointment/api/customers/organization/**").authenticated()
            .pathMatchers(HttpMethod.GET, "/api/authenticate/service/appointment/api/customers").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers("/api/authenticate/service/appointment/api/customers/**").permitAll()
            .pathMatchers(HttpMethod.GET, "/api/authenticate/service/appointment/api/services/**").permitAll()
            .pathMatchers("/api/authenticate/service/appointment/api/services/**").hasAnyAuthority(AuthoritiesConstants.MANAGER, AuthoritiesConstants.ADMIN)
            // OrganizationService
            .pathMatchers(HttpMethod.GET, "/api/authenticate/service/organization/api/opening-hours/organization/**").permitAll()
            .pathMatchers(HttpMethod.GET, "/api/authenticate/service/organization/api/working-hours/organization/**").permitAll()
            .pathMatchers(HttpMethod.GET, "/api/authenticate/service/organization/api/closing-times/organization/**").permitAll()
            .pathMatchers(HttpMethod.GET, "/api/authenticate/service/organization/api/employees/organization/**").permitAll()
            .pathMatchers(HttpMethod.GET, "/api/authenticate/service/organization/api/organizations/**").permitAll()
            .pathMatchers("/api/authenticate/service/organization/**").hasAnyAuthority(AuthoritiesConstants.MANAGER, AuthoritiesConstants.ADMIN)
            // OrganizationAppointmentService
            .pathMatchers("/api/authenticate/service/organizationappointment/api/slots").permitAll()
            .pathMatchers("/api/authenticate/service/organizationappointment/**").hasAuthority(AuthoritiesConstants.ADMIN)
            // PaymentService
            .pathMatchers(HttpMethod.POST, "/api/authenticate/service/payment/api/products").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers(HttpMethod.PUT, "/api/authenticate/service/payment/api/products/**").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers(HttpMethod.POST, "/api/authenticate/service/payment/api/prices").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers(HttpMethod.PUT, "/api/authenticate/service/payment/api/prices/**").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers(HttpMethod.GET, "/api/authenticate/service/payment/api/customers").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers("/api/authenticate/service/payment/api/stripe/events/**").permitAll()
            .pathMatchers("/api/authenticate/service/payment/**").authenticated()

            .pathMatchers("/api/authenticate/service/appointment/management/**").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers("/api/authenticate/service/organization/management/**").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers("/api/authenticate/service/organizationappointment/management/**").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers("/api/authenticate/service/payment/management/**").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers("/api/authenticate/**").hasAuthority(AuthoritiesConstants.ADMIN)

            .pathMatchers("/api/register").permitAll()
            .pathMatchers("/api/activate").permitAll()
            .pathMatchers("/api/account/reset-password/init").permitAll()
            .pathMatchers("/api/account/reset-password/finish").permitAll()
            .pathMatchers("/api/auth-info").permitAll()
            .pathMatchers("/api/admin/**").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers("/api/**").authenticated()
            .pathMatchers("/services/*/v3/api-docs").hasAuthority(AuthoritiesConstants.ADMIN)
            .pathMatchers("/services/**").authenticated()
            .pathMatchers("/management/health").permitAll()
            .pathMatchers("/management/health/**").permitAll()
            .pathMatchers("/management/info").permitAll()
            .pathMatchers("/management/prometheus").permitAll()
            .pathMatchers("/management/**").hasAuthority(AuthoritiesConstants.ADMIN);
        // @formatter:on
        return http.build();
    }
}
