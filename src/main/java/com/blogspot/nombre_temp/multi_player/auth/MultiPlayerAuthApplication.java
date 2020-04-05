package com.blogspot.nombre_temp.multi_player.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import reactor.netty.ReactorNetty;

@SpringBootApplication
public class MultiPlayerAuthApplication {

  public static void main(String[] args) {
    System.setProperty(ReactorNetty.ACCESS_LOG_ENABLED, "true");
    SpringApplication.run(MultiPlayerAuthApplication.class, args);
  }
}
