package com.bizzlog.gateway.filters;

import com.bizzlog.gateway.client.UserResponse;
import com.bizzlog.gateway.dto.ErrorResponseModel;
import com.bizzlog.gateway.utils.SecurityConstants;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Date;
import java.util.List;
import java.util.function.Predicate;

@Slf4j
@Component
public class AuthPreFilter   implements GlobalFilter {

    @Autowired
    private final WebClient.Builder webClientBuilder;

    @Autowired
    @Qualifier("excludedUrls")
    List<String> excludedUrls;


    private final ObjectMapper objectMapper;

    public AuthPreFilter(WebClient.Builder webClientBuilder, ObjectMapper objectMapper) {
        this.webClientBuilder = webClientBuilder;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        log.info("**************************************************************************");
        log.info("URL is - " + request.getURI().getPath());
        String bearerToken = request.getHeaders().getFirst(SecurityConstants.HEADER);
        log.info("Bearer Token: "+ bearerToken);
        log.info("************************ Pre Filter **************************************");

        String requestPath = exchange.getRequest().getPath().toString();
        if (isLoginOrRegistrationPath(requestPath)) {
            return chain.filter(exchange);
        }

        if(isSecured.test(request)) {
            log.info("************************ inside if **************************************");

            return webClientBuilder.build().post()
                    .uri("http://localhost:8081/api/v1/auth/validateToken")
                    .header(SecurityConstants.HEADER, bearerToken)
                    .retrieve()
                    .bodyToMono(UserResponse.class)
                    .map(response -> {
                        log.info("************************ inside map **************************************");
                        log.info(response.toString());
                        exchange.getRequest().mutate().header("username", response.getUserName());
//                        exchange.getRequest().mutate().header(SecurityConstants.ROLE, response.getRoles().stream().map(role->{
//                            return role.getName();
//                        }).toList().stream().collect(Collectors.joining(",")));

//                            exchange.getRequest().mutate().header("authorities", response.getAuthorities().stream().map(Authorities::getAuthority).reduce("", (a, b) -> a + "," + b));
//                            exchange.getRequest().mutate().header("auth-token", response.getToken());
                        log.info("************************ inside map 2 **************************************");
                        return exchange;
                    }).flatMap(chain::filter).onErrorResume(error -> {
                        log.info("Error Happened");
                        HttpStatus errorCode = null;
                        String errorMsg = "";
                        log.info("************************ 1st point in error **************************************");
                        if (error instanceof WebClientResponseException) {
                            log.info("************************ 2nd point in error **************************************");

                            WebClientResponseException webCLientException = (WebClientResponseException) error;
                            errorCode =  HttpStatus.BAD_GATEWAY;//webCLientException.getStatusCode();
                            errorMsg = webCLientException.getStatusText();
                            log.info("************************ 4th point in error **************************************");


                        } else {
                            log.info("************************ 3rd point in error **************************************");

                            errorCode = HttpStatus.BAD_GATEWAY;
                            errorMsg = HttpStatus.BAD_GATEWAY.getReasonPhrase();
                        }
//                            AuthorizationFilter.AUTH_FAILED_CODE
                        return onError(exchange, String.valueOf(errorCode.value()) ,errorMsg, "JWT Authentication Failed", errorCode);
                    });
        }

        return chain.filter(exchange);
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errCode, String err, String errDetails, HttpStatus httpStatus) {
        DataBufferFactory dataBufferFactory = exchange.getResponse().bufferFactory();
//        ObjectMapper objMapper = new ObjectMapper();
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        try {
            response.getHeaders().add("Content-Type", "application/json");
            ErrorResponseModel data = new ErrorResponseModel(errCode, err, errDetails, null, new Date());
            byte[] byteData = objectMapper.writeValueAsBytes(data);
            return response.writeWith(Mono.just(byteData).map(t -> dataBufferFactory.wrap(t)));

        } catch (JsonProcessingException e) {
            e.printStackTrace();

        }
        return response.setComplete();
    }

    private boolean isLoginOrRegistrationPath(String path) {
        // Define paths for login and registration APIs
        return path.contains("/login") || path.contains("/register")||path.contains("/refreshToken");
    }

    public Predicate<ServerHttpRequest> isSecured = request -> excludedUrls.stream().noneMatch(uri -> request.getURI().getPath().contains(uri));

}
