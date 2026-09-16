package com.certchain.certchain.dto.response;

import com.certchain.certchain.model.Role;

import java.util.UUID;

public record UserResponse(

        UUID id,

        String email,

        String fullName,

        Role role
) {
}