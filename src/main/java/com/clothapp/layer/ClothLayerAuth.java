package com.clothapp.layer;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class ClothLayerAuth {
    public static String generateIdentityToken(final String nonce, final String userId, final String keyPath, final String appId, final String providerId) {
        final Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("GMT"));
        calendar.setTime(new Date());
        calendar.add(Calendar.DATE, 1);
        ObjectNode jwtHeaderMap = new ObjectNode(JsonNodeFactory.instance);
        jwtHeaderMap.put("typ", "JWS");
        jwtHeaderMap.put("alg", "RS256");
        jwtHeaderMap.put("cty", "layer-eit;v=1");
        jwtHeaderMap.put("kid", appId); // Identifies the Layer Key ID used to sign the token
        ObjectNode jwtClaimMap = new ObjectNode(JsonNodeFactory.instance);
        jwtClaimMap.put("iss", providerId); // The Layer Provider ID
        jwtClaimMap.put("prn", userId);
        jwtClaimMap.put("iat", (int) (new Date().getTime() / 1000));
        jwtClaimMap.put("exp", (int) (calendar.getTime().getTime() / 1000));
        jwtClaimMap.put("nce", nonce);
        try {
            String base64Header = base64UrlEncode(jwtHeaderMap.toString().getBytes());
            String base64Claim = base64UrlEncode(jwtClaimMap.toString().getBytes());
            String concatenatedHeaderAndClaim = String.format("%s.%s", base64Header, base64Claim);
            PrivateKey privateKey = getPrivateKey(keyPath);
            byte[] signedString = sign(concatenatedHeaderAndClaim, privateKey);
            return String.format("%s.%s", concatenatedHeaderAndClaim, base64UrlEncode(signedString));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private static String base64UrlEncode(byte[] str) throws Exception {
        return new String(Base64.encodeBase64URLSafe(str));
    }

    public static PrivateKey getPrivateKey(String pathOfKey) throws Exception{
        InputStream res = pathOfKey.getClass().getResourceAsStream("/" + pathOfKey);
        Reader fRd = new BufferedReader(new InputStreamReader(res));
        PEMParser pemReader = new PEMParser(fRd);
        Object obj = pemReader.readObject();
        byte[] readByets = null;
        if (obj instanceof PEMKeyPair) {
            PrivateKeyInfo keyInfo = ((PEMKeyPair) obj).getPrivateKeyInfo();
            readByets = keyInfo.getEncoded();
        }
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(readByets);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    public static byte[] sign(String hashToEncrypt, PrivateKey key) throws Exception {
        Signature rsaSigner = Signature.getInstance("SHA256withRSA");
        rsaSigner.initSign(key);
        rsaSigner.update(hashToEncrypt.getBytes());
        return rsaSigner.sign();
    }
}