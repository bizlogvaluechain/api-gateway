package com.bizzlog.gateway;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Slf4j
@Component
public class AuthorizationTokenFilter implements GlobalFilter, Ordered {

//    @Value("${security.authentication.excluded-paths}")
//    private List<String> excludedPaths;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Get the requested path
        String requestPath = exchange.getRequest().getPath().toString();
        log.info("Request received with path:"+requestPath);

        // Skip token validation for login and registration APIs
        if (isLoginOrRegistrationPath(requestPath)) {
            // Continue with the filter chain without token validation
            return chain.filter(exchange);
        }

        // Retrieve the authorization token from the request headers
        String authorizationHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

        // You can now use the authorization token as needed
        log.info("Authorization Token: " + authorizationHeader);

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            // Extract the actual token after "Bearer "
            String authToken = authorizationHeader.substring(7);

            // You can now use the authToken as needed
            log.info("Actual Token: " + authToken);
        } else {
            // Throw a 403 Forbidden error
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access Denied");

        }

        // Continue with the filter chain
        return chain.filter(exchange);
    }

    private boolean isLoginOrRegistrationPath(String path) {
        // Define paths for login and registration APIs
        return path.contains("/login") || path.contains("/register");
    }

    @Override
    public int getOrder() {
        // Set the order in which the filter should be executed
        return Ordered.HIGHEST_PRECEDENCE;
    }
}

