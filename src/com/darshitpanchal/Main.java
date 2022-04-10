package com.darshitpanchal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.zip.DataFormatException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

public class Main {

	public static void main(String[] args) throws InvalidAlgorithmParameterException, ParseException, JOSEException,
			NoSuchAlgorithmException, IOException, DataFormatException {

		// The main FHIR bundle in the stringifies format variable
		String payloadJson = "{\"iss\":\"https://github.com/panchaldarshit/smart-health-card\",\"nbf\":1631290671.609,\"vc\":{\"type\":[\"https://smarthealth.cards#health-card\",\"https://smarthealth.cards#immunization\",\"https://smarthealth.cards#covid19\"],\"credentialSubject\":{\"fhirVersion\":\"4.0.1\",\"fhirBundle\":{\"resourceType\":\"Bundle\",\"type\":\"collection\",\"entry\":[{\"fullUrl\":\"resource:0\",\"resource\":{\"resourceType\":\"Patient\",\"name\":[{\"family\":\"Anyperson\",\"given\":[\"John\",\"B.\"]}],\"birthDate\":\"1951-01-20\"}},{\"fullUrl\":\"resource:1\",\"resource\":{\"resourceType\":\"Immunization\",\"status\":\"completed\",\"vaccineCode\":{\"coding\":[{\"system\":\"http://hl7.org/fhir/sid/cvx\",\"code\":\"207\"}]},\"patient\":{\"reference\":\"resource:0\"},\"occurrenceDateTime\":\"2021-01-01\",\"performer\":[{\"actor\":{\"display\":\"ABC General Hospital\"}}],\"lotNumber\":\"0000001\"}},{\"fullUrl\":\"resource:2\",\"resource\":{\"resourceType\":\"Immunization\",\"status\":\"completed\",\"vaccineCode\":{\"coding\":[{\"system\":\"http://hl7.org/fhir/sid/cvx\",\"code\":\"207\"}]},\"patient\":{\"reference\":\"resource:0\"},\"occurrenceDateTime\":\"2021-01-29\",\"performer\":[{\"actor\":{\"display\":\"ABC General Hospital\"}}],\"lotNumber\":\"0000007\"}}]}}}}";

		KeyPair keyPair = KeyPairData.generateKeyPair();
		JWK jwkKeyPair = KeyPairData.generateJwkKey(keyPair);

		String jwkThumbPrint = KeyPairData.generateThumbprint(jwkKeyPair);

		System.out.println("JWK Key Pair :::" + jwkKeyPair);
		System.out.println("JWK Thumbprint ::: " + jwkThumbPrint);

		// Generate JWSHeader
		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(jwkThumbPrint).customParam("zip", "DEF")
				.build();

		// Convert the payload JSON string to UTF-8 bytes array
		byte[] input = payloadJson.getBytes(StandardCharsets.UTF_8);
		// Deflate the payload UTF-8 bytes array
		byte[] compressedOutput = Data.compress(input);

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
		String numericModeQr = "shc:/" + Conversion.convertBase64ToNumeric(serialisedJws);

		System.out.println("Numeric QR::: => " + numericModeQr);

		System.out.println("\n:::::: Converting the SMART CARD to FHIR Bundle ::::::\n");

		String toDecodeNumericQrWithPrefix = numericModeQr;

		String toDecodeNumericQrWithoutPrefix = toDecodeNumericQrWithPrefix.substring(5);
		System.out.println("Numeric QR Code Without 'src:\\' prefix ::: " + toDecodeNumericQrWithoutPrefix);

		String base64EncodedString = Conversion.convertNumericToBase64(toDecodeNumericQrWithoutPrefix);
		System.out.println("Decode Numeric QR To Base64 ::: " + base64EncodedString);

		JWSObject decodedJws = JWSObject.parse(base64EncodedString);

		// Create a JWSVerifier object using the JWK Public Key
		JWSVerifier verifier = new ECDSAVerifier(((ECKey) jwkKeyPair).toPublicJWK());

		System.out.println("isVerified::: " + decodedJws.verify(verifier));

		byte[] decompressedJwsPayload = Data.decompress(decodedJws.getPayload().toBytes());

		String decompressedJsonData = new String(decompressedJwsPayload, StandardCharsets.UTF_8);
		System.out.println(decompressedJsonData);

	}
}
