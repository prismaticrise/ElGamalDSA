import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;

public class Utils {

    // Хеширует СОДЕРЖИМОЕ файла, а не его имя!
    public static BigInteger hash(String filename) throws NoSuchAlgorithmException, IOException {
        // Читаем ВСЕ байты файла
        byte[] fileBytes = Files.readAllBytes(Paths.get(filename));
        
        // Вычисляем SHA-256 от содержимого
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(fileBytes);
        
        // Преобразуем в положительный BigInteger
        return new BigInteger(1, hashBytes);
    }
}