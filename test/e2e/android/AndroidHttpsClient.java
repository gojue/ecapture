import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Minimal Android platform HTTPS workload.
 *
 * <p>Running this class with app_process deliberately exercises Conscrypt and the platform BoringSSL
 * library. A Go HTTPS binary is not a valid workload for the Android {@code tls} probe because Go
 * implements TLS without BoringSSL.
 */
public final class AndroidHttpsClient {
    private AndroidHttpsClient() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("usage: AndroidHttpsClient URL EXPECTED_TOKEN 1.2|1.3");
            System.exit(2);
        }

        TrustManager[] trustAll =
                new TrustManager[] {
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }

                        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

                        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    }
                };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustAll, new SecureRandom());

        String protocol;
        if ("1.2".equals(args[2])) {
            protocol = "TLSv1.2";
        } else if ("1.3".equals(args[2])) {
            protocol = "TLSv1.3";
        } else {
            throw new IllegalArgumentException("Unsupported TLS version: " + args[2]);
        }

        HostnameVerifier allowAnyHost = (hostname, session) -> true;
        HttpsURLConnection connection =
                (HttpsURLConnection) new URL(args[0]).openConnection();
        connection.setSSLSocketFactory(
                new ProtocolSocketFactory(context.getSocketFactory(), protocol));
        connection.setHostnameVerifier(allowAnyHost);
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(10_000);
        connection.setRequestProperty("Connection", "close");

        int status = connection.getResponseCode();
        InputStream input =
                status >= 400 ? connection.getErrorStream() : connection.getInputStream();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = input.read(buffer)) != -1) {
            body.write(buffer, 0, count);
        }
        input.close();
        connection.disconnect();

        String response = new String(body.toByteArray(), StandardCharsets.UTF_8);
        System.out.println("HTTP status: " + status);
        System.out.println(response);
        if (status != 200 || !response.contains(args[1])) {
            System.err.println("Expected response token not found: " + args[1]);
            System.exit(1);
        }
    }

    private static final class ProtocolSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final String[] protocols;

        ProtocolSocketFactory(SSLSocketFactory delegate, String protocol) {
            this.delegate = delegate;
            this.protocols = new String[] {protocol};
        }

        private Socket configure(Socket socket) {
            ((SSLSocket) socket).setEnabledProtocols(protocols);
            return socket;
        }

        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }

        public Socket createSocket(Socket socket, String host, int port, boolean close)
                throws IOException {
            return configure(delegate.createSocket(socket, host, port, close));
        }

        public Socket createSocket(String host, int port) throws IOException {
            return configure(delegate.createSocket(host, port));
        }

        public Socket createSocket(
                String host, int port, InetAddress localAddress, int localPort) throws IOException {
            return configure(delegate.createSocket(host, port, localAddress, localPort));
        }

        public Socket createSocket(InetAddress address, int port) throws IOException {
            return configure(delegate.createSocket(address, port));
        }

        public Socket createSocket(
                InetAddress address, int port, InetAddress localAddress, int localPort)
                throws IOException {
            return configure(delegate.createSocket(address, port, localAddress, localPort));
        }
    }
}
