package com.darshitpanchal;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class Main {

    public static void main(String[] args) throws InvalidAlgorithmParameterException, ParseException, JOSEException, NoSuchAlgorithmException, IOException, DataFormatException {

        // The main FHIR bundle in the stringifies format variable
        String payloadJson = "{\"iss\":\"https://github.com/panchaldarshit/smart-health-card\",\"nbf\":1631290671.609,\"vc\":{\"type\":[\"https://smarthealth.cards#health-card\",\"https://smarthealth.cards#immunization\",\"https://smarthealth.cards#covid19\"],\"credentialSubject\":{\"fhirVersion\":\"4.0.1\",\"fhirBundle\":{\"resourceType\":\"Bundle\",\"type\":\"collection\",\"entry\":[{\"fullUrl\":\"resource:0\",\"resource\":{\"resourceType\":\"Patient\",\"name\":[{\"family\":\"Anyperson\",\"given\":[\"John\",\"B.\"]}],\"birthDate\":\"1951-01-20\"}},{\"fullUrl\":\"resource:1\",\"resource\":{\"resourceType\":\"Immunization\",\"status\":\"completed\",\"vaccineCode\":{\"coding\":[{\"system\":\"http://hl7.org/fhir/sid/cvx\",\"code\":\"207\"}]},\"patient\":{\"reference\":\"resource:0\"},\"occurrenceDateTime\":\"2021-01-01\",\"performer\":[{\"actor\":{\"display\":\"ABC General Hospital\"}}],\"lotNumber\":\"0000001\"}},{\"fullUrl\":\"resource:2\",\"resource\":{\"resourceType\":\"Immunization\",\"status\":\"completed\",\"vaccineCode\":{\"coding\":[{\"system\":\"http://hl7.org/fhir/sid/cvx\",\"code\":\"207\"}]},\"patient\":{\"reference\":\"resource:0\"},\"occurrenceDateTime\":\"2021-01-29\",\"performer\":[{\"actor\":{\"display\":\"ABC General Hospital\"}}],\"lotNumber\":\"0000007\"}}]}}}}";

        // Generate EC key pair with P-256 curve
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(Curve.P_256.toECParameterSpec());
        KeyPair keyPair = gen.generateKeyPair();

        // Convert the EC key pair to JWK format
        JWK jwkKeyPair = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
                .keyIDFromThumbprint()
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(Algorithm.parse("ES256"))
                .privateKey((ECPrivateKey) keyPair.getPrivate())
                .build();

        // Private Key hardcoded for testing
        String testJwkJson = "{\"kty\":\"EC\",\"d\":\"QM2mj1m8B4wM4bV2HgPhGhBBqVh7TvVrpsidmgzWYyQ\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"PBhGG7BiQdpr6OxYcHxKUnnPzNPdy6VhMEKLbFiGycA\",\"x\":\"xwGorbxo6B5Cn7Bsrcq32S6_CriNpmFCWzx_flucf_g\",\"y\":\"_6yBcVHtEwobdSw_Z9-IUsaXGIsxvMfOxEXOiqieyW4\",\"alg\":\"ES256\"}";
        JWK testJwkKeyPair = JWK.parse(testJwkJson);
        jwkKeyPair = testJwkKeyPair;

        // Compute the thumbprint of the private key
        String jwkThumbPrint = String.valueOf(jwkKeyPair.computeThumbprint());

        System.out.println("JWK Key Pair :::" + jwkKeyPair);
        System.out.println("JWK Thumbprint ::: " + jwkThumbPrint);

        // Generate JWSHeader
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(jwkThumbPrint)
                .customParam("zip", "DEF")
                .build();

        // Convert the payload JSON string to UTF-8 bytes array
        byte[] input = payloadJson.getBytes(StandardCharsets.UTF_8);
        // Deflate the payload UTF-8 bytes array
        byte[] compressedOutput = compress(input);

        System.out.println("Compressed Output bytes[] ::: " + Arrays.toString(compressedOutput));

        // Initiate the variable of type "Payload" which contains the UTF-8 bytes array
        Payload payload = new Payload(compressedOutput);

        // Add the JWS Header and Payload bytes array to the JWSObject
        JWSObject jws = new JWSObject(jwsHeader, payload);

        // Compute a ECDSASigner using the JWK Key Pair
        JWSSigner signer = new ECDSASigner((ECKey) jwkKeyPair);

        // Sign the JWSObject variable using the ECDSASigner object
        jws.sign(signer);

        // Serialize the JWSObject variable to generate Base64 String
        String serialisedJws = jws.serialize();

        System.out.println("Serialised JWS ::: " + serialisedJws);

        // Convert the Base64 serialised JWS to Numeric mode for QR
        String numericModeQr = "shc:/" + convertBase64ToNumeric(serialisedJws);

        System.out.println("Numeric QR::: => " + numericModeQr);

        System.out.println("\n:::::: Converting the SMART CARD to FHIR Bundle ::::::\n");

        String toDecodeNumericQrWithPrefix = numericModeQr;

        String toDecodeNumericQrWithoutPrefix = toDecodeNumericQrWithPrefix.substring(5);
        System.out.println("Numeric QR Code Without 'src:\\' prefix ::: " + toDecodeNumericQrWithoutPrefix);

        String base64EncodedString = convertNumericToBase64(toDecodeNumericQrWithoutPrefix);
        System.out.println("Decode Numeric QR To Base64 ::: " + base64EncodedString);

        JWSObject decodedJws = JWSObject.parse(base64EncodedString);

        // Create a JWSVerifier object using the JWK Public Key
        JWSVerifier verifier = new ECDSAVerifier(((ECKey) jwkKeyPair).toPublicJWK());

        System.out.println("isVerified::: " + decodedJws.verify(verifier));

        byte[] decompressedJwsPayload = decompress(decodedJws.getPayload().toBytes());

        String decompressedJsonData = new String(decompressedJwsPayload, StandardCharsets.UTF_8);
        System.out.println(decompressedJsonData);

    }
    public static byte[] compress(byte[] data) throws IOException {
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        deflater.setInput(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);

        deflater.finish();
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer); // returns the generated code... index
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();

        return output;
    }

    public static byte[] decompress(byte[] data) throws IOException, DataFormatException {
        Inflater inflater = new Inflater(true);
        inflater.setInput(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[1024];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();

        return output;
    }

    public static String convertBase64ToNumeric(String serialisedJws) {

        System.out.println("JWS Length ::: " + serialisedJws.length());
        String numericQr = "";

        for (int i = 0; i < serialisedJws.length(); i++) {
            int c = serialisedJws.charAt(i) - 45;
            int d = (int)Math.floor(c / 10);
            int e = c % 10;
            numericQr += Integer.toString(d) + Integer.toString(e);
        }

        return numericQr;
    }

    public static String convertNumericToBase64(String numericQr) {

        String replacedString = numericQr.replaceAll("/[^0-9]/", "");
        System.out.println(replacedString);

        String[] replacedString2 = replacedString.split("(?<=\\G..)");
        System.out.println(Arrays.toString(replacedString2));
        String base64Qr = "";

        for (int i = 0; i < replacedString2.length; i++) {
            base64Qr += (char)(Integer.parseInt(replacedString2[i]) + 45);
        }

        return base64Qr;
    }


}
