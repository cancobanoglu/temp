package signartsmimeserviceclient;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import tr.biznet.signart.shell.pkcs11.Pkcs11Shell;
import tr.biznet.signart.shell.pkcs11.Pkcs11ShellException;

/**
 * Pkcs11Shell usage
 * 
 * @author aidikut
 */
public class Pkcs11Util {
    public static List getCertificates() {
        List certificates = new LinkedList();
        Pkcs11Shell pkcs11Shell = initializeShell();
        try {
            certificates = pkcs11Shell.getCertificates();
        } catch (Pkcs11ShellException ex) {
            System.out.println("An error occured while getting certificates. (" + ex.getErrorCode() + " " + ex.getMessage() + ")");
        }
        deinitializeShell(pkcs11Shell);
        return certificates;
    }

    public static byte[] sign(byte[] dataToSign, X509Certificate cert, String pin) {
        byte[] signedData = null;
        Pkcs11Shell pkcs11Shell = initializeShell();
        try {
            pkcs11Shell.login(cert, pin, true, true);
            signedData = pkcs11Shell.sign(cert, dataToSign);
        } catch (Pkcs11ShellException ex) {
            System.out.println("An error occured while signing data. (" + ex.getErrorCode() + " " + ex.getMessage() + ")");
            ex.printStackTrace();
        }
        deinitializeShell(pkcs11Shell);
        return signedData;
    }

    public static List batchSign(List dataToSigns, X509Certificate cert, String pin) {
        List signedDataList = new LinkedList();
        Pkcs11Shell pkcs11Shell = initializeShell();
        try {
            pkcs11Shell.login(cert, pin, true, true);

            for (Iterator it = dataToSigns.iterator(); it.hasNext();) {
                byte[] dataToSign = (byte[])it.next();
                byte[] signedData = pkcs11Shell.sign(cert, dataToSign);
                signedDataList.add(signedData);
            }
        } catch (Pkcs11ShellException ex) {
            System.out.println("An error occured while signing data. (" + ex.getErrorCode() + " " + ex.getMessage() + ")");
            ex.printStackTrace();
            return null;
        } finally {
            deinitializeShell(pkcs11Shell);
        }
        return signedDataList;
    }

    private static Pkcs11Shell initializeShell() {
        //add possible pkcs11 implementations (can be dynamic, but these are all of the supported modules in Turkey)
        List supportedModules = new LinkedList();
        supportedModules.add("gclib.dll"); //gemplus (Turktrust, E-Güven, Tubitak)
        supportedModules.add("akisp11.dll"); //tubitak akis (Tübitak)
        supportedModules.add("aetpkss1.dll"); //genuine (E-Güven)
        supportedModules.add("siecap11.dll"); //siemens (Türktrust)
        supportedModules.add("iidp11.dll"); //netid (E-Tugra)
        supportedModules.add("etpkcs11.dll"); //alaaddin (E-Güven)
        
        String applicationPath = Pkcs11Util.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        try {
            applicationPath = URLDecoder.decode(applicationPath, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            ex.printStackTrace(System.out);
        }

        String arch;
        if (System.getProperty("sun.arch.data.model").equals("64")) {//64 bit jvm windows
            arch = "64";
        } else {//32 bit jvm windows
            arch = "32";
        }

        File jarPath = new File(applicationPath);
        if (!jarPath.isDirectory()) {
            jarPath = jarPath.getParentFile();
        }
        File pkcs11wrapperFile = new File(jarPath, "libpkcs11wrapper" + arch + ".dll");
        Pkcs11Shell pkcs11Shell = new Pkcs11Shell("C:\\Users\\alper.uzanulu\\Desktop\\lib\\libpkcs11wrapper64.dll");
        Iterator it = supportedModules.iterator();
        while (it.hasNext()) {
            String module = (String) it.next();
            try {
                pkcs11Shell.addModule(module);
            } catch (Pkcs11ShellException ex) {
                System.out.println(module + " is not supported in this computer (" + ex.getErrorCode() + " " + ex.getMessage() + ")");
            }
        }
        return pkcs11Shell;
    }

    private static void deinitializeShell(Pkcs11Shell pkcs11Shell) {
        try {
            pkcs11Shell.deinitialize();
        } catch (Pkcs11ShellException ex) {
            System.out.println("Cannot deinitialize pkcs11 shell. (" + ex.getErrorCode() + " " + ex.getMessage() + ")");
        }
    }
}
