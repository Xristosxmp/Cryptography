import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class SHA_256 {
    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        new BasicSHA256("abc");
        new SHA256_RSA("abc");
    }
}

class BasicSHA256{
    BasicSHA256(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        BigInteger n = new BigInteger(1 , md.digest(input.getBytes(StandardCharsets.UTF_8)));
        StringBuilder hex = new StringBuilder(n.toString(16));
        while(hex.length() < 64) hex.insert(0 ,'0');
        System.out.println("SHA(\"" +input + "\") => " + hex.toString());
    }
}

class SHA256_RSA{
    private KeyPair GetKeyPair() throws NoSuchAlgorithmException{
        KeyPairGenerator kP = KeyPairGenerator.getInstance("RSA");
        kP.initialize(2048);
        return kP.generateKeyPair();
    }
    private byte[] Sign(byte[] H , PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(privateKey);
        s.update(H);
        return s.sign();
    }
    private boolean verify(byte[] H , byte[] sD , PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(H);
        return verifier.verify(sD);
    }
    SHA256_RSA(String input) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        KeyPair KP = GetKeyPair();
        PublicKey PuK = KP.getPublic();
        PrivateKey PrK = KP.getPrivate();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] HD = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        byte[] SD = Sign(HD , PrK);
        boolean Verify = verify(HD , SD , PuK);
        System.out.println(input + " {Validation} => " + Verify);
    }



}