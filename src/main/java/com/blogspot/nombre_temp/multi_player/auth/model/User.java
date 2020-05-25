package com.blogspot.nombre_temp.multi_player.auth.model;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonFormat.Shape;
import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class User {
  private String username;

  private Date sessionExpirationDate;

  private List<String> roles;

  public User() {
  }

  public User(UserDetails userDetails, Date sessionExpirationDate) {
    username = userDetails.getUsername();
    roles = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    this.sessionExpirationDate = sessionExpirationDate;
  }

  public String getUsername() {
    return username;
  }

  @JsonFormat(shape = Shape.NUMBER)
  @Schema(type = "integer", format = "int64", description = "Epoch time in milliseconds")
  public Date getSessionExpirationDate() {
    return sessionExpirationDate;
  }

  public List<String> getRoles() {
    return roles;
  }
}
