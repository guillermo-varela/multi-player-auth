package com.blogspot.nombre_temp.multi_player.auth.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@RestController
@RequestMapping(produces = MediaType.APPLICATION_JSON_VALUE)
public @interface RestControllerJson {
  @AliasFor(annotation = RestController.class)
  String value() default "";
}
