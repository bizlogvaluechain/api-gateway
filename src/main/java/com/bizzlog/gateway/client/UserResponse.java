package com.bizzlog.gateway.client;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.List;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class UserResponse {

    private Long id;
    private String userId;
    private String userName;
    private String clientId;
    private Boolean status;
    private Set<String> roles;

    private List<String> permissions;




}
