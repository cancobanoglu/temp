/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package signartsmimeserviceclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.activation.DataSource;

/**
 *
 * @author alper.uzanulu
 */
public class InputStreamDataSource implements DataSource{
    private InputStream inputStream;

    public InputStreamDataSource(InputStream inputStream) {
        this.inputStream = inputStream;
    }
    
    
    @Override
    public InputStream getInputStream() throws IOException {
       return this.inputStream;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getContentType() {
        return "*/*";
    }

    @Override
    public String getName() {
        return "InputStreamDataSource";
    }
    
}
