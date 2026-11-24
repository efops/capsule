import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * A small web service. Each replica answers with its own id, so you can see
 * which one a request reached when the capsule is scaled.
 */
public class Hello {
    public static void main(String[] args) throws Exception {
        String replica = UUID.randomUUID().toString().substring(0, 8);
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/", exchange -> {
            byte[] body = ("Hello from Java " + Runtime.version().feature() + " in a capsule, replica " + replica + ".\n")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        System.out.println("listening on 8080");
    }
}
