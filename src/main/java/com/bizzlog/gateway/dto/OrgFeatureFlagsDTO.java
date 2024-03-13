package com.bizzlog.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
@Data
@AllArgsConstructor
@NoArgsConstructor
public class OrgFeatureFlagsDTO {
    private String feature;
    private Boolean enabled;
}
