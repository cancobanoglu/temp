import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Test;
import signartsmimeserviceclient.SignArtSmimeService;
import tr.biznet.msign.service.ws.smime.SignatureResponse;
import tr.biznet.msign.service.ws.smime.VerificationResponse;

/**
 *
 * @author alper.uzanulu
 */
public class SignArtSmimeServiceTest {

    private SignArtSmimeService service;

    public SignArtSmimeServiceTest() {
        service = new SignArtSmimeService();
    }

    @Test
    public void testVerify() {
        VerificationResponse response;
        try {
            response = service.verify("token_signed_ileti_cades_bes.eml");
        } catch (Exception ex) {
            Logger.getLogger(SignArtSmimeServiceTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void testMobileSign() {
        SignatureResponse response;
        try {
            response = service.signWithMobile();
        } catch (Exception ex) {
            Logger.getLogger(SignArtSmimeServiceTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void testMobileSignProfile4() {
        SignatureResponse response;
        try {
            response = service.signWithMobileProfile4();
        } catch (Exception ex) {
            Logger.getLogger(SignArtSmimeServiceTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void testSignWithToken() {
        SignatureResponse response;
        try {
            response = service.signWithToken();
        } catch (Exception ex) {
            Logger.getLogger(SignArtSmimeServiceTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void testSignWithTokenProfile4() {
        SignatureResponse response;
        try {
            response = service.signWithTokenProfile4();
        } catch (Exception ex) {
            Logger.getLogger(SignArtSmimeServiceTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}