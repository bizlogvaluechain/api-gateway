//package com.bizzlog.gateway.client;
//
//import org.springframework.cloud.openfeign.FeignClient;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RequestMethod;
//import org.springframework.web.bind.annotation.RequestParam;
//
//@FeignClient(value = "iam", url = "http://localhost:8080/api/v1")
//public interface IAMClient {
//
//    @RequestMapping(method = RequestMethod.POST, value = "/validate")
//    UserResponse getUserByToken(@RequestParam("token") String token);
//
//}
