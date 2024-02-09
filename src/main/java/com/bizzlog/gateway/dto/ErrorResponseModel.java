package com.bizzlog.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Date;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class ErrorResponseModel implements Serializable {
    private static final long serialVersionUID = 1L;
    private String errCode;
    private String err;
    private String errDetails;
    private Object o;
    private Date date;
}
