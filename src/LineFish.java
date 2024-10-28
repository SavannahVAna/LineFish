import java.io.FileNotFoundException;
import java.net.UnknownHostException;

public class LineFish {
    public static void main(String[] args) throws UnknownHostException, FileNotFoundException {
        String file = args[0];
        if (args.length > 1) {
            if (args[1].equals("-t")) {
                //int n = Integer.parseInt(args[2]);
                String[] a = {args[0],args[2]};
                Main2.main(a);
            }
        }
        else {
            Main2.main(new String[] {file});
        }
    }
}
