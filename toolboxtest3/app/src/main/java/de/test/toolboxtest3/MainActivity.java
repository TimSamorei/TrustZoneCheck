package de.test.toolboxtest3;

import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.security.auth.x500.X500Principal;

public class MainActivity extends AppCompatActivity {

    KeyStore ks;
    KeyPair kp;
    private final String alias = "ALIAS_";
    private final String pkcs8key = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDh00azpk0vYqhA\n" +
            "gLYijtLIV9mYUBLn+BurQTMapYhX9vH2PUIhR9pao4YMRDe5msej1rFMJ4/Qo6qN\n" +
            "2E1M/DLuBbqZz0YN9JnBLAqx4ceKek6uoGgb9YkjgvWjJ/rrLrfL1bPgcAJ9Iv8M\n" +
            "mPA7YtGcE9lLci+OmIUg0JeTqldPvDEjdcxzO/X026jEFeD4w9y/aWK6wNAciA3T\n" +
            "5VsjRlqijI/HGRzm7kw3eHpMmgespKP7mv3QWRa+AiDBfC+pAEvyHlGEtlRrJ0L3\n" +
            "+gNPSiRPJObVc5fmmuBAEVc0p16ZlzaDDSjnerTedy2npIFyps7NB56JXvGf+yd7\n" +
            "AVCVfch1AgMBAAECggEAGO4dGQob7UZD8tMCyG/h/zILmJAGdktiqpZJEQEDO0rM\n" +
            "zXVXzprDFUyGKOaDDF90+LZj3ldjvhHDa2NcrUoOSU6imgZS4omFS9kT2S1mvPfh\n" +
            "pc+ZjrSdjikP+xIX1kzTB5KxB+71p2DsrTRZGQVAxK1ASN7zNxfJYqUEhs3AU9Hq\n" +
            "uA3nxBepUcvuAwPEgGJhavySs4MooqNYrUwi/sjx3C6Mq5rFSpJLHVbf8aOPLud1\n" +
            "tus3e3H1Nt/MPiqsZaixoTn7qkdJN2ShMTtt079C4cw1s3onV0a6V0cLnXQgCB8Q\n" +
            "N1TxWji1FH7/0LymQSB7LjM/21yKQonjuOphc40zxQKBgQDyAVvctbm9F/pQQKdo\n" +
            "t5LDurB6g2/Te23wUSE9cWhjrRXTL4FyR6gF6wFDreEi7AiYE4xnhBJKL28NyR+c\n" +
            "AEFt/9H6RyihopRoe391Y6wcGgYdHl2wPdA6AI2yRrz3HHJFT1+npOYbfT2DR2Mq\n" +
            "qk0quEmce90pJnFlsBr97hMufwKBgQDu4mOKZt/nN30cZhIr0iCChOrPFzp6SJKw\n" +
            "93e2abjcIjWi3OSqL3oocq4nbBsf5bRDKYTcMUNqDhitogdabqR++tbfCIPqPanL\n" +
            "8tCR13sfIkr/7xFGrzGO7h5PP4TxQ4BKY8sz8PLQmzdRttKEnLtJ5k3E9YnLDhKu\n" +
            "nyBo4JK3CwKBgQDpyCJDzlHFt/oZuLuAT4Y6CokdcQeAFwaXVuhzgLDFSZmBz6yP\n" +
            "B2XrgaBRDxIkODv9HTVPcqhwfe4cNSSSATUz3COuUTuRGYuge10fu8+xvfoV+xWq\n" +
            "gaw7u/kmNWuqlBJXnlvbiVK5T30y6q2Ds8yj7i8+OfHmJLr67urET068ZQKBgQDa\n" +
            "TQRODCj88RZiB1z/sqyG2dSCn2WPLhbvpZY+mmqWsKR3SomkhHKL2BEScZZwFcgf\n" +
            "wCdr2ZETsAIZWoKBv66PY8dMVknGm8c5W5ICVPpsvzfunpgZEiylwzDrls50dA0e\n" +
            "7gdaVgxvWgi5oerLyTbWF6JmJURgzWGBNmW1sdQhdQKBgQC060b4P8n+MZQ7GMIt\n" +
            "gUxZgjO3jQsNP5mIcbYk9uAeAzEb+/tmxsLXN8YyAqPbgH3Bq+ZRw8y9Wo9G4Ejq\n" +
            "kKTof7CbKu+Dx/im4czJ9nBgC4CIUPUGKE2decabQuwkakocKATkwQw+o98ETN9l\n" +
            "zvU7HfEfDHzd0jyugMlRBK6sHA==\n" +
            "-----END PRIVATE KEY-----";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView privateKeyText = findViewById(R.id.textview);
        //privateKeyText.setText(pkcs8key);

        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader rdr = new BufferedReader(new StringReader(pkcs8key));
        String line;
        try {
            while ((line = rdr.readLine()) != null) {
                pkcs8Lines.append(line);
            }
        } catch (java.io.IOException e) {
            Log.d("import", "IOException");
            e.printStackTrace();
        }

        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+", "");

        byte[] pkcs8EncodedBytes = Base64.decode(pkcs8Pem, Base64.DEFAULT);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            Log.d("import", "NoSuchAlgorithmException");
            e.printStackTrace();
        }
        PrivateKey privKey = null;
        try {
            privKey = kf.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            Log.d("import", "InvalidKeySpecException");
            e.printStackTrace();
        }

        Log.d("import", "imported keys: " + privKey.getClass());
        Log.d("import", "imported keys: " + privKey.getAlgorithm());
        Log.d("import", "imported keys: " + privKey.getFormat());
        Log.d("import", "imported keys: " + privKey.getEncoded());
        Log.d("import", "imported keys: " + privKey.toString());
        Log.d("import", "imported keys: " + privKey.toString());

        //testprivkey("testString", privKey);

        //isInHardware();

        createKeys();

        privateKeyText.setText("" + isInHardware());

        testprivkey("testString");

        swapkeys(privKey);

        testprivkey("testString");

        privateKeyText.setText("" + isInHardware());

    }

    private boolean isInHardware() {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(alias, null);
            PrivateKey key = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo;
            keyInfo = factory.getKeySpec(key, KeyInfo.class);
            Log.d("import", "isInHardware: " + keyInfo.isInsideSecureHardware());
            return keyInfo.isInsideSecureHardware();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return true;
    }

    private void testprivkey(String inputStr, PrivateKey privKey) {
        Signature s = null;
        try {
            s = Signature.getInstance("SHA256withRSA");
            s.initSign(privKey);
            byte[] data = inputStr.getBytes();
            s.update(data);
            byte[] signature = s.sign();
            String result = Base64.encodeToString(signature, Base64.DEFAULT);
            Log.d("import", "sign: " + result);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private void testprivkey(String inputStr) {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(alias, null);
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
            byte[] data = inputStr.getBytes();
            s.update(data);
            byte[] signature = s.sign();
            String result = Base64.encodeToString(signature, Base64.DEFAULT);
            Log.d("import", "sign: " + result);

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    public void createKeys(){
        Calendar start = new GregorianCalendar();
        Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 1);

        KeyPairGenerator kpGenerator = null;
        try {
            kpGenerator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        } catch (NoSuchAlgorithmException e) {
            Log.d("import", "NoSuchAlgorithmException");
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            Log.d("import", "NoSuchProviderException");
            e.printStackTrace();
        }
        AlgorithmParameterSpec spec;
        spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setCertificateSubject(new X500Principal("CN=" + alias))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setCertificateSerialNumber(BigInteger.valueOf(1337))
                .setCertificateNotBefore(start.getTime())
                .setCertificateNotAfter(end.getTime())
                //.setIsStrongBoxBacked(true)
                .build();
        try {
            kpGenerator.initialize(spec);
        } catch (InvalidAlgorithmParameterException e) {
            Log.d("import", "InvalidAlgorithmParameterException");
            e.printStackTrace();
        }

        KeyPair kp = kpGenerator.generateKeyPair();
        Log.d("imported keys", "Public Key is: " + kp.getPublic().toString());
    }

    public void swapkeys(PrivateKey privKey) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            ks.setKeyEntry(alias, privKey, null, ks.getCertificateChain(alias));
            Log.d("import", "Keys swapped");
        } catch (KeyStoreException e) {
            Log.d("import", "KeyStoreException");
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
