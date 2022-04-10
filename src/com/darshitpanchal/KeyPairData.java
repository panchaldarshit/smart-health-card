package com.darshitpanchal;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;

public class KeyPairData {

	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		// Generate EC key pair with P-256 curve
		KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
		gen.initialize(Curve.P_256.toECParameterSpec());

		return gen.generateKeyPair();
	}

	public static JWK generateJwkKey(KeyPair keyPair) throws JOSEException {
		// Convert the EC key pair to JWK format
		JWK jwkKeyPair = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic()).keyIDFromThumbprint()
				.keyUse(KeyUse.SIGNATURE).algorithm(Algorithm.parse("ES256"))
				.privateKey((ECPrivateKey) keyPair.getPrivate()).build();

		return jwkKeyPair;
	}
}
