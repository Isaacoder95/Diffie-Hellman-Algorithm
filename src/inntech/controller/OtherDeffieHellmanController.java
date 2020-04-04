package inntech.controller;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

import inntech.model.PublicKeyEntity;

@RestController
@RequestMapping("/other-deffie-hellman")
public class OtherDeffieHellmanController {
	
	
	@Autowired
	RestTemplate restTemplate;
	
	@GetMapping("/create-shared-key")
	public String createSharedKey() {
		
		System.out.println("ALICE: Generate DH keypair ...");
        
        String sharedSecret=null;
		try {
			KeyPairGenerator aliceKpairGen;
			aliceKpairGen = KeyPairGenerator.getInstance("DH");
		
	        aliceKpairGen.initialize(2048);
	        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
	        
	        // Alice creates and initializes her DH KeyAgreement object
	        System.out.println("ALICE: Initialization ...");
	        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
	        aliceKeyAgree.init(aliceKpair.getPrivate());
	        
	        // Alice encodes her public key, and sends it over to Bob.
	        //byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();
	        PublicKeyEntity publicKeyAliceEntity=new PublicKeyEntity();
	        publicKeyAliceEntity.setPublicKey(aliceKpair.getPublic().getEncoded());
	        publicKeyAliceEntity.setFormat(aliceKpair.getPublic().getFormat());
	
	        ObjectMapper Obj = new ObjectMapper(); 
	        
	        try { 
	  
	            // get Oraganisation object as a json string 
	            String jsonStr = Obj.writeValueAsString(publicKeyAliceEntity); 
	  
	            // Displaying JSON String 
	            System.out.println("JSON "+jsonStr); 
	        } 
	  
	        catch (IOException e) { 
	            e.printStackTrace(); 
	        }  
	        System.out.println("PublicKeyAlice bytes "+publicKeyAliceEntity.getPublicKey());
	        
	        MultiValueMap<String, String> headers= new LinkedMultiValueMap<>();
			headers.add("Content-type", MediaType.APPLICATION_JSON.toString());
			HttpEntity<PublicKeyEntity> requestEntity = new HttpEntity<PublicKeyEntity>(publicKeyAliceEntity, headers);
			
			ResponseEntity<PublicKeyEntity> responsePKString=restTemplate.exchange("http://localhost:8080/deffie-hellman/create-shared-key", HttpMethod.POST, requestEntity, PublicKeyEntity.class);
			
			PublicKeyEntity publicKeyBobEntity=responsePKString.getBody();
			
			X509EncodedKeySpec x509BobKeySpec = new X509EncodedKeySpec(publicKeyBobEntity.getPublicKey());
			KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
			PublicKey bobPubKey = aliceKeyFac.generatePublic(x509BobKeySpec);
	        
	        aliceKeyAgree.doPhase(bobPubKey, true);
	        
	        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
	        sharedSecret=toHexString(aliceSharedSecret);
	        System.out.println("Alice secret: " + sharedSecret);
	        
	        
	        
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return sharedSecret;
		
	}
	
	private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
	
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
