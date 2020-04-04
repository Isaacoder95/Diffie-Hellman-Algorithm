package dev.icn.controller;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.validation.Valid;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.icn.model.PublicKeyEntity;

@RestController
@RequestMapping("/deffie-hellman")
public class DeffieHellmanController {

	
	@PostMapping("/create-shared-key")
	public PublicKeyEntity createSharedKey(@Valid @RequestBody PublicKeyEntity publicAliceKeyEntity) {
		
        byte[] bobPubKeyEnc=null;
        PublicKeyEntity publicKeyBobEntity=null;
		
		try {
			
			KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
			
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicAliceKeyEntity.getPublicKey());
			
	        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);
	        DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey)alicePubKey).getParams();
			
			//DHParameterSpec  dhParamFromAlicePubKey=new DHParameterSpec(publicKeyEntity.getP(), publicKeyEntity.getG(), publicKeyEntity.getL());
			KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
			bobKpairGen.initialize(dhParamFromAlicePubKey);
			
			KeyPair bobKpair = bobKpairGen.generateKeyPair();
			
			// Bob creates and initializes his DH KeyAgreement object
	        System.out.println("BOB: Initialization ...");
	        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
	        bobKeyAgree.init(bobKpair.getPrivate());
			
	     // Bob encodes his public key, and sends it over to Alice.
	        bobPubKeyEnc = bobKpair.getPublic().getEncoded();
		
	        publicKeyBobEntity=new PublicKeyEntity();
	        publicKeyBobEntity.setPublicKey(bobPubKeyEnc);
	        publicKeyBobEntity.setFormat(bobKpair.getPublic().getFormat());
	        
			System.out.println("BOB: Execute PHASE1 ...");	
	        bobKeyAgree.doPhase(alicePubKey, true);

	        byte[] bobSharedSecret=bobKeyAgree.generateSecret();
	        
	        System.out.println("PublicKeyBob bytes "+bobPubKeyEnc);
	        
	        System.out.println("Bob secret: " +toHexString(bobSharedSecret)); 
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        System.out.println("ALICE: Execute PHASE1 ...");
        return publicKeyBobEntity;
        //return publicKeyEntity;


	}
	
    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
	
	
}
