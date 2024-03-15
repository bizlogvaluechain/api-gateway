package com.bizzlog.gateway.filters;

import com.bizzlog.gateway.client.UserResponse;
import com.bizzlog.gateway.dto.ErrorResponseModel;
import com.bizzlog.gateway.dto.OrgFeatureFlagsDTO;
import com.bizzlog.gateway.dto.Privilege;
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
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.function.Predicate;

@Slf4j
@Component
public class AuthPreFilter   implements GlobalFilter {

    @Autowired
    private final WebClient.Builder webClientBuilder;

//    private final List<String> fePaths=List.of("api/v1/auth","api/v1/users","api/v1/cos","api/v1/tcs","api/v1/config");
//    private final Map<String, Boolean> pathRestrictions = Map.of(
//            "/api/v1/tcs", true
//    );

    private static final Map<String, List<String>> featureAPIsMapping = new HashMap<>();
    private static final Map<String, List<String>> methodPrivilegesMapping = new HashMap<>();
    private static final Map<String, List<String>> privilegesAPIsMapping = new HashMap<>();
    static{
        featureAPIsMapping.put("ticket-creation", List.of("tcs"));
        featureAPIsMapping.put("zones", List.of("zones"));
        methodPrivilegesMapping.put("write", List.of("POST,GET,PUT"));
        methodPrivilegesMapping.put("delete", List.of("GET,DELETE"));
        methodPrivilegesMapping.put("read", List.of("GET"));
        methodPrivilegesMapping.put("all", List.of("POST,GET,PUT,DELETE"));
        privilegesAPIsMapping.put("ticket-creation",List.of("tcs"));
    }
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
        log.info("URL is - " + request.getURI().getPath());
        String bearerToken = request.getHeaders().getFirst(SecurityConstants.HEADER);
        log.info("Bearer Token: "+ bearerToken);
        log.info("Entering to Pre Filter");

        String requestPath = exchange.getRequest().getPath().toString();
        if (isLoginOrRegistrationPath(requestPath)) {
            return chain.filter(exchange);
        }

        if(isSecured.test(request)) {

            return webClientBuilder.build().post()
                    .uri("http://localhost:8081/api/v1/auth/validateToken")
                    .header(SecurityConstants.HEADER, bearerToken)
                    .retrieve()
                    .bodyToMono(UserResponse.class)
                    .map(response -> {
                        if (!ObjectUtils.isEmpty(response)) {
                            log.info(response.toString());
                           log.info("org features--> {}",response.getFeatureFlags());
                            if (!validateFeatures(requestPath, response.getFeatureFlags())) {
                                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                                throw new WebClientResponseException(HttpStatusCode.valueOf(405), "ACCESS FORBIDDEN FOR USER", null, null, null, null);
                            }
                            if (!validatePrivileges(request, response.getProfile().getPrivileges())) {
                                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                                throw new WebClientResponseException(HttpStatusCode.valueOf(405), "ACCESS FORBIDDEN FOR USER", null, null, null, null);
                            }
                            exchange.getRequest().mutate().header("username", response.getUserName());
                        }
                        return exchange;
                    }).flatMap(chain::filter).onErrorResume(error -> {
                        log.info("Error Happened");
                        HttpStatus errorCode = null;
                        String errorMsg = "";
                        if (error instanceof WebClientResponseException) {
                            WebClientResponseException webCLientException = (WebClientResponseException) error;
                            if(webCLientException.getStatusCode().isSameCodeAs(HttpStatusCode.valueOf(405))){
                                errorCode =  HttpStatus.FORBIDDEN;//webCLientException.getStatusCode();
                                errorMsg = webCLientException.getStatusText();
                                return onError(exchange, String.valueOf(errorCode.value()) ,errorMsg, "Access Denied for this Request", errorCode);
                            }
                            else {
                                errorCode =  HttpStatus.BAD_GATEWAY;//webCLientException.getStatusCode();
                                errorMsg = webCLientException.getStatusText();
                            }
                        } else {
                            errorCode = HttpStatus.BAD_GATEWAY;
                            errorMsg = HttpStatus.BAD_GATEWAY.getReasonPhrase();
                        }
//                            AuthorizationFilter.AUTH_FAILED_CODE
                        return onError(exchange, String.valueOf(errorCode.value()) ,errorMsg, "JWT Authentication Failed", errorCode);
                    });
        }

        return chain.filter(exchange);
    }


    private boolean validateFeatures(String path, List<OrgFeatureFlagsDTO> featureFlags) {
        List<String> disabledFeatures=featureFlags.stream().filter(x ->!x.getEnabled()).map(OrgFeatureFlagsDTO::getFeature).toList();
        log.info("path: {} and disabledFeatures: {}", path, disabledFeatures);
        boolean ffStatus = disabledFeatures.stream()
                .map(featureAPIsMapping::get)
                .flatMap(List::stream)
                .anyMatch(path::contains);
        return !ffStatus;
    }

    private boolean validatePrivileges(ServerHttpRequest request,List<Privilege> privileges) {
        String requestMethod=request.getMethod().toString();
        String path=request.getURI().getPath();

        log.info("path: {} and disabledFeatures: {}", path, privileges);
        boolean privilegeStatus = privileges.stream()
                .map(privilege -> {
                    String userPrivilege="";
                    if(privilege.getPrivilege().split(".").length==2){
                        userPrivilege= Arrays.stream(privilege.getPrivilege().split(".")).toList().get(0);
                    }
                    return privilegesAPIsMapping.get(userPrivilege);
                })
                .flatMap(List::stream)
                .anyMatch(path::contains);
        boolean methodStatus = privileges.stream()
                .map(privilege -> {
                    String method="";
                    if(privilege.getPrivilege().split(".").length==2){
                        method= Arrays.stream(privilege.getPrivilege().split(".")).toList().get(1);
                    }
                    return methodPrivilegesMapping.get(method);
                })
                .flatMap(List::stream)
                .anyMatch(requestMethod::contains);
        return !privilegeStatus&&!methodStatus;
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
        return path.contains("/login") || path.contains("/machine-token")||path.contains("/refreshToken")||path.contains("/forgot-password");
    }

    public Predicate<ServerHttpRequest> isSecured = request -> excludedUrls.stream().noneMatch(uri -> request.getURI().getPath().contains(uri));

}
