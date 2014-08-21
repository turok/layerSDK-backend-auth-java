package com.clothapp.layer;

import org.junit.Test;

public class ClothLayerAuthTest {

    @Test
    public void testMain() throws Exception {
        //TODO: Need place layer.pem into main/resources
        String generatedString = ClothLayerAuth.generateIdentityToken("z3dIA2LiBF0jnvg+uUvjCKyCLjcQCmuqzwfUKGMLR0gSv9qnnft6BvtQPlm1uEyKc04L9CPpHvVrgnpy5ft/PA==", "685173528236398", "layer.pem", "testAppId", "testProviderId");
        System.out.println("Generated identity token:");
        System.out.println(generatedString);

    }
}