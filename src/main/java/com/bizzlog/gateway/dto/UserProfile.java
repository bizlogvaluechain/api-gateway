package com.bizzlog.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class UserProfile {

    private long id;

    private String profile;

    private Role role;

    private List<Privilege> privileges;
}
