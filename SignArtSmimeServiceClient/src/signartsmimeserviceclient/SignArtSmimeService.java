package signartsmimeserviceclient;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import javax.activation.DataHandler;
import tr.biznet.msign.service.ws.smime.DataToSignRequest;
import tr.biznet.msign.service.ws.smime.DataToSignResponse;
import tr.biznet.msign.service.ws.smime.FingerPrintRequest;
import tr.biznet.msign.service.ws.smime.FingerprintResponse;
import tr.biznet.msign.service.ws.smime.SignaturePolicyIdentifier;
import tr.biznet.msign.service.ws.smime.SignatureResponse;
import tr.biznet.msign.service.ws.smime.UserInfo;
import tr.biznet.msign.service.ws.smime.VerificationResponse;



/**
 *
 * @author alper.uzanulu
 */
public class SignArtSmimeService {
    private static final String URL2 = "http://demo.biznet.com.tr/SignArt/SignArtSmimeService?wsdl";
    private static final String URL1 = "http://localhost:8080/SignArt/SignArtSmimeService?wsdl";
    private static final String API_USERNAME = "alperdemo";
    private static final String API_USERPASSWORD = "alperdemo";
    private String applicationPath;

    public SignArtSmimeService() {
        applicationPath = SignArtSmimeService.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        try {
            applicationPath = URLDecoder.decode(applicationPath, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            ex.printStackTrace(System.out);
        }
        applicationPath = applicationPath.replace("build/classes/", "");
    }
        
    
    public VerificationResponse verify(String fileName) throws Exception {
        InputStream fis = new FileInputStream(new File(applicationPath + "etc/" + fileName));
        InputStreamDataSource inputStreamDataSource = new InputStreamDataSource(fis);
        DataHandler dataHandler = new DataHandler(inputStreamDataSource);
        VerificationResponse verificationResponse = verify(dataHandler, getUserInfo());
        return verificationResponse;
    }
    
    public SignatureResponse signWithToken() throws Exception {
        InputStream is = new FileInputStream(new File(applicationPath + "etc/ileti.eml"));
        InputStreamDataSource isDataSource = new InputStreamDataSource(is);
        
        DataHandler dataHandler = new DataHandler(isDataSource);
        X509Certificate cert = getX509Certificate();
        String encodedCertificate = Base64.encodeBytes(cert.getEncoded());

        // alabileceği değerler CADES_BES, CADES_X_LONG, CADES_X_LONG_T1, CADES_A, CADES_A_NOESC, PADES_LTV
        // CADES_BES hariç diğerlerinde zaman damgası bulunmaktadır.
        String signatureFormat = "CADES_BES";

        DataToSignRequest dataToSignRequest = new DataToSignRequest();
        dataToSignRequest.setBase64Certificate(encodedCertificate);
        dataToSignRequest.setData(dataHandler);
        dataToSignRequest.setSignatureFormat(signatureFormat);
        
        DataToSignResponse dataToSignResponse = prepareDataToSign(dataToSignRequest, getUserInfo());

        byte[] signature = Pkcs11Util.sign(Base64.decode(dataToSignResponse.getDataToSignBase64()), cert, "1234");
        SignatureResponse signatureResponse = sign(Base64.encodeBytes(signature), dataToSignResponse.getSignToken(), getUserInfo());
        saveSignedFile(signatureResponse.getSignedData(), "token_signed_ileti_" + signatureFormat.toLowerCase() + ".eml");
        return signatureResponse;
    }
    
    
     public SignatureResponse signWithTokenProfile4() throws Exception {
        InputStream is = new FileInputStream(new File(applicationPath + "etc/ileti.eml"));
        InputStreamDataSource isDataSource = new InputStreamDataSource(is);
        
        DataHandler dataHandler = new DataHandler(isDataSource);
        X509Certificate cert = getX509Certificate();
        String encodedCertificate = Base64.encodeBytes(cert.getEncoded());
        
        SignaturePolicyIdentifier signaturePolicyIdentifier = new SignaturePolicyIdentifier();
        signaturePolicyIdentifier.setHashValue("/zm9KUYzg/abIFKsR0OeBs58O4ZG6Ii25a4+RroIEXo="); // profil dökümanı sha-256 base64 hash değeri
        signaturePolicyIdentifier.setHashAlgorithmOID("2.16.840.1.101.3.4.2.1"); //sha-256 oid
        signaturePolicyIdentifier.setSignaturePolicyOID("2.16.792.1.61.0.1.5070.3.3.1"); //profile4 oid
        signaturePolicyIdentifier.setSpuri("www.www.com");
        signaturePolicyIdentifier.setSpUserNotice("www");

        // alabileceği değerler CADES_BES, CADES_X_LONG, CADES_X_LONG_T1, CADES_A, CADES_A_NOESC, PADES_LTV
        // CADES_BES hariç diğerlerinde zaman damgası bulunmaktadır.
        String signatureFormat = "CADES_X_LONG";

        DataToSignRequest dataToSignRequest = new DataToSignRequest();
        dataToSignRequest.setBase64Certificate(encodedCertificate);
        dataToSignRequest.setData(dataHandler);
        dataToSignRequest.setSignatureFormat(signatureFormat);
        dataToSignRequest.setSignaturePolicyIdentifier(signaturePolicyIdentifier);
        
        DataToSignResponse dataToSignResponse = prepareDataToSign(dataToSignRequest, getUserInfo());

        byte[] signature = Pkcs11Util.sign(Base64.decode(dataToSignResponse.getDataToSignBase64()), cert, "1234");
        SignatureResponse signatureResponse = sign(Base64.encodeBytes(signature), dataToSignResponse.getSignToken(), getUserInfo());
        saveSignedFile(signatureResponse.getSignedData(), "token_signed_ileti_profile4_" + signatureFormat.toLowerCase() + ".eml");
        return signatureResponse;
    }
    
    
    public SignatureResponse signWithMobile() throws Exception {
        InputStream fis = new FileInputStream(new File(applicationPath + "etc/ileti.eml"));
        InputStreamDataSource inputStreamDataSource = new InputStreamDataSource(fis);
        DataHandler dataHandler = new DataHandler(inputStreamDataSource);

        // alabileceği değerler CADES_BES, CADES_X_LONG, CADES_X_LONG_T1, CADES_A, CADES_A_NOESC
        // CADES_BES hariç diğerlerinde zaman damgası bulunmaktadır,
        String signatureFormat = "CADES_BES";
        FingerPrintRequest fingerPrintRequest = new FingerPrintRequest();
        fingerPrintRequest.setData(dataHandler);
        fingerPrintRequest.setMessage("mobileSign imza denemesi");
        fingerPrintRequest.setOperator("Turkcell");
        fingerPrintRequest.setPhoneNumber("05549929099");
        fingerPrintRequest.setSignatureFormat(signatureFormat);

        FingerprintResponse fingerprintResponse = prepareFingerprint(fingerPrintRequest, getUserInfo());
        System.out.println(fingerprintResponse.getFingerprint());
        SignatureResponse signatureResponse = mobileSign(fingerprintResponse.getSignToken(), getUserInfo());
        saveSignedFile(signatureResponse.getSignedData(), "mobile_signed_ileti_" + signatureFormat.toLowerCase() + ".eml");
        return signatureResponse;
    }

    
    public SignatureResponse signWithMobileProfile4() throws Exception {
        InputStream fis = new FileInputStream(new File(applicationPath + "etc/ileti.eml"));
        InputStreamDataSource inputStreamDataSource = new InputStreamDataSource(fis);
        DataHandler dataHandler = new DataHandler(inputStreamDataSource);

        SignaturePolicyIdentifier signaturePolicyIdentifier = new SignaturePolicyIdentifier();
        signaturePolicyIdentifier.setHashValue("/zm9KUYzg/abIFKsR0OeBs58O4ZG6Ii25a4+RroIEXo="); // profil dökümanı sha-256 base64 hash değeri
        signaturePolicyIdentifier.setHashAlgorithmOID("2.16.840.1.101.3.4.2.1"); //sha-256 oid
        signaturePolicyIdentifier.setSignaturePolicyOID("2.16.792.1.61.0.1.5070.3.3.1"); //profile4 oid
        signaturePolicyIdentifier.setSpuri("www.www.com");
        signaturePolicyIdentifier.setSpUserNotice("www");
        // alabileceği değerler CADES_BES, CADES_X_LONG, CADES_X_LONG_T1, CADES_A, CADES_A_NOESC
        // CADES_BES hariç diğerlerinde zaman damgası bulunmaktadır,
        String signatureFormat = "CADES_X_LONG";
        FingerPrintRequest fingerPrintRequest = new FingerPrintRequest();
        fingerPrintRequest.setData(dataHandler);
        fingerPrintRequest.setMessage("mobileSign imza denemesi");
        fingerPrintRequest.setOperator("Turkcell");
        fingerPrintRequest.setPhoneNumber("05549929099");
        fingerPrintRequest.setSignatureFormat(signatureFormat);
        fingerPrintRequest.setSignaturePolicyIdentifier(signaturePolicyIdentifier);

        FingerprintResponse fingerprintResponse = prepareFingerprint(fingerPrintRequest, getUserInfo());
        System.out.println(fingerprintResponse.getFingerprint());
        SignatureResponse signatureResponse = mobileSign(fingerprintResponse.getSignToken(), getUserInfo());
        saveSignedFile(signatureResponse.getSignedData(), "mobile_signed_ileti_profile4_" + signatureFormat.toLowerCase() + ".eml");
        return signatureResponse;
    }
    
    
    private void saveSignedFile(byte[] signedData, String fileName) throws Exception {
        FileOutputStream fos = new FileOutputStream(new File(applicationPath + "etc/" + fileName));
        fos.write(signedData);
        fos.close();
    }

    private UserInfo getUserInfo() {
        UserInfo userInfo = new UserInfo();
        userInfo.setUsername(API_USERNAME);
        userInfo.setPassword(API_USERPASSWORD);
        return userInfo;
    }
    
     private byte[] getData(String path) throws Exception {
        FileInputStream fis = new FileInputStream(path);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[16384];

        while ((nRead = fis.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        buffer.flush();
        byte[] dataToVerify = buffer.toByteArray();
        return dataToVerify;
    }
     
       private X509Certificate getX509Certificate() throws Exception {
        // akıllı karttan sertifikaları seçip listede ilk gelen sertifikayı kullanıyoruz
        List list = Pkcs11Util.getCertificates();
        Iterator iter = list.iterator();
        X509Certificate cert = null;
        while (iter.hasNext()) {
            cert = ((tr.biznet.signart.shell.wrapper.Certificate) iter.next()).getCertificate();
            break;
        }
        return cert;
    }

    private static SignatureResponse mobileSign(java.lang.String signToken, tr.biznet.msign.service.ws.smime.UserInfo userInfo) throws MalformedURLException {
        tr.biznet.msign.service.ws.smime.SignArtSmimeService_Service service = new tr.biznet.msign.service.ws.smime.SignArtSmimeService_Service(new URL(URL1));
        tr.biznet.msign.service.ws.smime.SignArtSmimeService port = service.getSignArtSmimeServicePort();
        return port.mobileSign(signToken, userInfo);
    }

    private static DataToSignResponse prepareDataToSign(tr.biznet.msign.service.ws.smime.DataToSignRequest dataToSignRequest, tr.biznet.msign.service.ws.smime.UserInfo userInfo) throws MalformedURLException {
        tr.biznet.msign.service.ws.smime.SignArtSmimeService_Service service = new tr.biznet.msign.service.ws.smime.SignArtSmimeService_Service(new URL(URL1));
        tr.biznet.msign.service.ws.smime.SignArtSmimeService port = service.getSignArtSmimeServicePort();
        return port.prepareDataToSign(dataToSignRequest, userInfo);
    }

    private static FingerprintResponse prepareFingerprint(tr.biznet.msign.service.ws.smime.FingerPrintRequest fingerPrintRequest, tr.biznet.msign.service.ws.smime.UserInfo userInfo) throws MalformedURLException {
        tr.biznet.msign.service.ws.smime.SignArtSmimeService_Service service = new tr.biznet.msign.service.ws.smime.SignArtSmimeService_Service(new URL(URL1));
        tr.biznet.msign.service.ws.smime.SignArtSmimeService port = service.getSignArtSmimeServicePort();
        return port.prepareFingerprint(fingerPrintRequest, userInfo);
    }

    private static SignatureResponse sign(java.lang.String signature, java.lang.String signToken, tr.biznet.msign.service.ws.smime.UserInfo userInfo) throws MalformedURLException {
        tr.biznet.msign.service.ws.smime.SignArtSmimeService_Service service = new tr.biznet.msign.service.ws.smime.SignArtSmimeService_Service(new URL(URL1));
        tr.biznet.msign.service.ws.smime.SignArtSmimeService port = service.getSignArtSmimeServicePort();
        return port.sign(signature, signToken, userInfo);
    }

    private static VerificationResponse verify(javax.activation.DataHandler smimeMessage, tr.biznet.msign.service.ws.smime.UserInfo userInfo) throws MalformedURLException {
        tr.biznet.msign.service.ws.smime.SignArtSmimeService_Service service = new tr.biznet.msign.service.ws.smime.SignArtSmimeService_Service(new URL(URL1));
        tr.biznet.msign.service.ws.smime.SignArtSmimeService port = service.getSignArtSmimeServicePort();
        return port.verify(smimeMessage, userInfo);
    }
 
    
}
