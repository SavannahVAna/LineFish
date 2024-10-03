import java.io.*;

public class PcapReader {
    public InputStream openPcap(String filename) throws FileNotFoundException {
        try{
            return new BufferedInputStream(new FileInputStream(filename));
        } catch (FileNotFoundException e) {
            System.out.println("File not found: " + filename);
        }
        return null;
    }
}
