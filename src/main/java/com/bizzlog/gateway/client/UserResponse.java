package com.bizzlog.gateway.client;

import com.bizzlog.gateway.dto.OrgFeatureFlagsDTO;
import com.bizzlog.gateway.dto.UserProfile;
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
    private Long orgId;
    private Boolean status;
    private UserProfile profile;
    private List<OrgFeatureFlagsDTO> featureFlags;
}
