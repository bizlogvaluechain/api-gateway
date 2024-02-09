package com.bizzlog.gateway.client;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserResponse {
    private Long id;
    private String userId;
    private String userName;
    private String clientId;
    private Boolean status;
    private List<UserRole> roles;
    private List<String> permissions;
}
