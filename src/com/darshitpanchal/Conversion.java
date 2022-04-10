package com.darshitpanchal;

import java.util.Arrays;

public class Conversion {
	public static String convertBase64ToNumeric(String serialisedJws) {

		System.out.println("JWS Length ::: " + serialisedJws.length());
		String numericQr = "";

		for (int i = 0; i < serialisedJws.length(); i++) {
			int c = serialisedJws.charAt(i) - 45;
			int d = (int) Math.floor(c / 10);
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
			base64Qr += (char) (Integer.parseInt(replacedString2[i]) + 45);
		}

		return base64Qr;
	}
}
