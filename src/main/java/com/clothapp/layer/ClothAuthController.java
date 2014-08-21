package com.clothapp.layer;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Created by turok on 8/19/14.
 */
@Controller
@EnableAutoConfiguration
public class ClothAuthController {
    @Value("${appId}")
    private String appId;
    @Value("${providerId}")
    private String providerId;

    @RequestMapping("/getIdentityToken")
    @ResponseBody
    public ReturnObject getIdentityToken(@RequestParam("nonce") String nonce, @RequestParam("userId") String userId) {
        ReturnObject object = new ReturnObject();
        object.setToken(ClothLayerAuth.generateIdentityToken(nonce, userId, "layer.pem", appId, providerId));
        return object;
    }

    public static void main(String[] args) throws Exception {
        SpringApplication.run(ClothAuthController.class, args);
    }

    private static class ReturnObject {
        private String token;

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }
    }
}
