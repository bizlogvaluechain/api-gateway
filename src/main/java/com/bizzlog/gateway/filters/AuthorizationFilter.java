package com.bizzlog.gateway.filters;

import com.bizzlog.gateway.dto.ErrorResponseModel;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bizzlog.gateway.utils.SecurityConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Date;
import java.util.List;
import java.util.function.Predicate;


//@Component
//@RefreshScope
@Slf4j
//@Component
public class AuthorizationFilter implements GlobalFilter {

	
//	@Value("${spring.gateway.excludedURLs}")
//	private String urlsStrings;
	
	@Autowired
	@Qualifier("excludedUrls")
	List<String> excludedUrls;
	
	public static final String AUTH_FAILED_CODE="ERR_AUTH_FAIL";
	
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
//		excludedUrls = Arrays.asList(urlsStrings);
		ServerHttpRequest req = exchange.getRequest();
		log.info("**************************************************************************");
		log.info("inside auth filter");
		log.info("URL is - " + req.getURI().getPath());
		if(isSecured.test(req)) {
			try {
				boolean hasAccess = authorization(req);
				if(!hasAccess) {
					log.info("Token Ivalid!");
					log.info("**************************************************************************");
					return this.onError(exchange, "Authorization header is invalid", HttpStatus. UNAUTHORIZED);
				}
			} catch (RuntimeException e) {
				log.info("Token Expired!");
				log.info("**************************************************************************");
				return this.onError(exchange, "Authorization header has expired", HttpStatus.UNAUTHORIZED);
			} catch (Exception e) {
				log.info("Token Ivalid!");
				log.info("**************************************************************************");
				return this.onError(exchange, "Authorization header is invalid", HttpStatus.UNAUTHORIZED);
			}
		}	
		log.info("**************************************************************************");
		return chain.filter(exchange);
	}
	
	private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
		DataBufferFactory dataBufferFactory = exchange.getResponse().bufferFactory();
	    ObjectMapper objMapper = new ObjectMapper();
	    ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);
	    try {
	    	response.getHeaders().add("Content-Type", "application/json");
			ErrorResponseModel data = new ErrorResponseModel(AUTH_FAILED_CODE, "JWT Error", err, null, new Date());
			byte[] byteData = objMapper.writeValueAsBytes(data);
	        return response.writeWith(Mono.just(byteData).map(t -> dataBufferFactory.wrap(t)));
	        
		} catch (JsonProcessingException  e) {
			e.printStackTrace();
		}
        return response.setComplete();
    }
	
	public Predicate<ServerHttpRequest> isSecured = request -> excludedUrls.stream().noneMatch(uri -> request.getURI().getPath().contains(uri));

	
	 private boolean authorization(ServerHttpRequest request) {
	        String role = request.getHeaders().getFirst(SecurityConstants.ROLE);
	        // base on role validate the request url has permissions.

	        return true;
	    }
}
