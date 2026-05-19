package com.goggles.gateway_server;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
class GatewayServerApplicationTests {

  @MockitoBean
  ReactiveJwtDecoder jwtDecoder;

  @Test
  void contextLoads() {}
}
