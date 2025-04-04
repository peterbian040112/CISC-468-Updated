import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;

import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.HKDFParameters;

class CryptoManager {
    private X25519PrivateKeyParameters staticPrivateKey;
    private X25519PublicKeyParameters staticPublicKey;

    public CryptoManager() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] privateKeyBytes = new byte[32];
        random.nextBytes(privateKeyBytes);
        this.staticPrivateKey = new X25519PrivateKeyParameters(privateKeyBytes, 0);
        this.staticPublicKey = this.staticPrivateKey.generatePublicKey();
    }

    public byte[] getStaticPubKey() {
        return staticPublicKey.getEncoded();
    }

    public byte[] performKeyExchange(X25519PublicKeyParameters peerStaticPub, X25519PublicKeyParameters peerEphemeralPub, X25519PrivateKeyParameters ephemeralPriv, byte[] salt) throws Exception {
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(ephemeralPriv);
        byte[] sharedSecret = new byte[32];
        agreement.calculateAgreement(peerEphemeralPub, sharedSecret, 0);

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(sharedSecret, salt, null));
        byte[] sessionKey = new byte[32];
        hkdf.generateBytes(sessionKey, 0, 32);
        return sessionKey;
    }

    public byte[] encryptFile(byte[] data, byte[] key) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[12];
        random.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] encrypted = cipher.doFinal(data);

        return ByteBuffer.allocate(nonce.length + encrypted.length)
                .put(nonce).put(encrypted).array();
    }

    public byte[] decryptFile(byte[] ciphertext, byte[] key) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
        byte[] nonce = new byte[12];
        buffer.get(nonce);
        byte[] ct = new byte[buffer.remaining()];
        buffer.get(ct);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        return cipher.doFinal(ct);
    }
}

public class SecureShareClient {
    private String name;
    private int port;
    private CryptoManager crypto;
    private JmDNS jmdns;
    private Map<String, Tuple<byte[], InetSocketAddress>> peers = new HashMap<>();
    private Map<String, byte[]> sessionKeys = new HashMap<>();
    private ExecutorService executor = Executors.newCachedThreadPool();

    static class Tuple<X, Y> {
        public final X x;
        public final Y y;
        public Tuple(X x, Y y) { this.x = x; this.y = y; }
    }

    private InetAddress getLocalIPv4Address() throws SocketException {
        for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!ni.isUp() || ni.isLoopback()) continue;
            for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                    return addr;
                }
            }
        }
        throw new RuntimeException("Could not determine local IPv4 address");
    }

    public SecureShareClient(String name, int port) throws Exception {
        this.name = name;
        this.port = port;
        this.crypto = new CryptoManager();
        InetAddress localAddress = getLocalIPv4Address();
        System.out.println("Using local IPv4 address: " + localAddress.getHostAddress());
        this.jmdns = JmDNS.create("172.20.10.3");

        String pubKey = Base64.getEncoder().encodeToString(crypto.getStaticPubKey());
        String text = "pubkey=" + pubKey;

        ServiceInfo serviceInfo = ServiceInfo.create(
            "_secure-share._tcp.local.",
            name,
            port,
            0,
            0,
            false,
            text
        );

        jmdns.registerService(serviceInfo);

        jmdns.addServiceListener("_secure-share._tcp.local.", new ServiceListener() {
            @Override
            public void serviceAdded(ServiceEvent event) {
                ServiceInfo info = jmdns.getServiceInfo(event.getType(), event.getName());
                if (info != null && !info.getName().equals(name)) {
                    byte[] peerPubKey = Base64.getDecoder().decode(info.getPropertyString("pubkey"));
                    String peerId = bytesToHex(peerPubKey).substring(0, 16);
                    peers.put(peerId, new Tuple<>(peerPubKey, new InetSocketAddress(info.getInetAddresses()[0], info.getPort())));
                    System.out.println("Discovered new peer: " + info.getName() + " at " + info.getInetAddresses()[0] + ":" + info.getPort());
                }
            }

            @Override
            public void serviceRemoved(ServiceEvent event) {
                String peerId = event.getName().split("\\.")[0].substring(0, 8);
                peers.remove(peerId);
                System.out.println("Peer removed: " + peerId);
            }

            @Override
            public void serviceResolved(ServiceEvent event) {}
        });

        executor.submit(this::startServer);
    }

    private void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started on port " + port);
            while (true) {
                Socket conn = serverSocket.accept();
                System.out.println("Accepted connection from " + conn.getInetAddress());
                executor.submit(() -> handleConnection(conn));
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void handleConnection(Socket conn) {
        try (conn; DataInputStream in = new DataInputStream(conn.getInputStream());
             DataOutputStream out = new DataOutputStream(conn.getOutputStream())) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }
            byte[] data = baos.toByteArray();
            System.out.println("Received data, length: " + data.length + " bytes");

            if (new String(data, StandardCharsets.UTF_8).startsWith("HANDSHAKE")) {
                System.out.println("Processing handshake request...");
                processHandshake(conn, data);
            } else if (new String(data, StandardCharsets.UTF_8).startsWith("REQUEST_LIST")) {
                System.out.println("Processing file list request...");
                File sharedDir = new File("shared");
                String files = sharedDir.exists() ? String.join(";", sharedDir.list()) : "";
                out.write(("FILE_LIST|" + files).getBytes(StandardCharsets.UTF_8));
            } else if (new String(data, StandardCharsets.UTF_8).startsWith("FILE_DATA")) {
                System.out.println("Receiving file data...");
                String[] parts = new String(data, StandardCharsets.UTF_8).split("\\|", 2);
                byte[] content = parts[1].getBytes(StandardCharsets.UTF_8);
                String peerId = bytesToHex(Arrays.copyOfRange(content, 0, 8));
                int delimiterIndex = new String(content, StandardCharsets.UTF_8).indexOf("||");
                byte[] fileHash = Arrays.copyOfRange(content, 8, delimiterIndex);
                byte[] encrypted = Arrays.copyOfRange(content, delimiterIndex + 2, content.length);

                byte[] sessionKey = sessionKeys.get(peerId);
                if (sessionKey != null) {
                    byte[] plaintext = crypto.decryptFile(encrypted, sessionKey);
                    byte[] calcHash = MessageDigest.getInstance("SHA-256").digest(plaintext);
                    if (!Arrays.equals(calcHash, fileHash)) {
                        System.out.println("Warning: file integrity check failed!");
                        return;
                    }
                    new File("received_files").mkdirs();
                    try (FileOutputStream fos = new FileOutputStream("received_files/" + peerId + "_file")) {
                        fos.write(plaintext);
                    }
                    System.out.println("Received file from " + peerId);
                } else {
                    System.out.println("No session key for peer " + peerId);
                }
            } else {
                System.out.println("Unknown request type: " + new String(data, StandardCharsets.UTF_8).substring(0, Math.min(20, data.length)));
            }
        } catch (Exception e) {
            System.err.println("Connection error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private int findDelimiter(byte[] data, int start) {
        for (int i = start; i < data.length; i++) {
            if (data[i] == '|') return i;
        }
        return -1;
    }

    private void processHandshake(Socket conn, byte[] data) throws Exception {
        int firstDelimiter = findDelimiter(data, 0);
        int secondDelimiter = findDelimiter(data, firstDelimiter + 1);
        if (firstDelimiter == -1 || secondDelimiter == -1 || secondDelimiter >= data.length) {
            System.out.println("Invalid handshake format");
            return;
        }
        byte[] peerStaticPubBytes = Arrays.copyOfRange(data, firstDelimiter + 1, secondDelimiter);
        byte[] peerEphPubBytes = Arrays.copyOfRange(data, secondDelimiter + 1, data.length);
        if (peerStaticPubBytes.length != 32 || peerEphPubBytes.length != 32) {
            System.out.println("Invalid key length: static=" + peerStaticPubBytes.length + ", ephemeral=" + peerEphPubBytes.length);
            return;
        }

        X25519PublicKeyParameters peerStaticPub = new X25519PublicKeyParameters(peerStaticPubBytes, 0);
        X25519PublicKeyParameters peerEphPub = new X25519PublicKeyParameters(peerEphPubBytes, 0);

        SecureRandom random = new SecureRandom();
        byte[] ephemeralPrivBytes = new byte[32];
        random.nextBytes(ephemeralPrivBytes);
        X25519PrivateKeyParameters ephemeralPriv = new X25519PrivateKeyParameters(ephemeralPrivBytes, 0);
        X25519PublicKeyParameters myEphPub = ephemeralPriv.generatePublicKey();

        try (DataOutputStream out = new DataOutputStream(conn.getOutputStream())) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write("HANDSHAKE_OK|".getBytes(StandardCharsets.UTF_8));
            baos.write(crypto.getStaticPubKey());
            baos.write("|".getBytes(StandardCharsets.UTF_8));
            baos.write(myEphPub.getEncoded());
            out.write(baos.toByteArray());
        }

        byte[] salt = ByteBuffer.allocate(peerStaticPubBytes.length + crypto.getStaticPubKey().length)
                .put(peerStaticPubBytes).put(crypto.getStaticPubKey()).array();
        byte[] sessionKey = crypto.performKeyExchange(peerStaticPub, peerEphPub, ephemeralPriv, salt);
        String peerId = bytesToHex(peerStaticPubBytes).substring(0, 8 );
        sessionKeys.put(peerId, sessionKey);
        System.out.println("Session established with peer ID: " + peerId);
        System.out.println("Session key: " + bytesToHex(sessionKey));
    }

    public void connectToPeer(String address) throws Exception {
        String[] parts = address.contains(":") ? address.split(":") : new String[]{address, "8080"};
        System.out.println("Attempting to connect to " + parts[0] + ":" + parts[1]);
        try (Socket s = new Socket()) {
            s.setSoTimeout(10000);
            s.connect(new InetSocketAddress(parts[0], Integer.parseInt(parts[1])), 10000);
            System.out.println("Connection established to " + parts[0] + ":" + parts[1]);
            try (DataOutputStream out = new DataOutputStream(s.getOutputStream());
                 DataInputStream in = new DataInputStream(s.getInputStream())) {
                SecureRandom random = new SecureRandom();
                byte[] ephemeralPrivBytes = new byte[32];
                random.nextBytes(ephemeralPrivBytes);
                X25519PrivateKeyParameters ephemeralPriv = new X25519PrivateKeyParameters(ephemeralPrivBytes, 0);
                X25519PublicKeyParameters ephemeralPub = ephemeralPriv.generatePublicKey();

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write("HANDSHAKE|".getBytes(StandardCharsets.UTF_8));
                baos.write(crypto.getStaticPubKey());
                baos.write("|".getBytes(StandardCharsets.UTF_8));
                baos.write(ephemeralPub.getEncoded());
                out.write(baos.toByteArray());
                System.out.println("Handshake sent, waiting for response");

                byte[] response = new byte[1024];
                int bytesRead = in.read(response);
                if (bytesRead > 0) {
                    int firstDelimiter = findDelimiter(response, 0);
                    int secondDelimiter = findDelimiter(response, firstDelimiter + 1);
                    if (firstDelimiter == -1 || secondDelimiter == -1 || secondDelimiter >= bytesRead) {
                        System.out.println("Invalid handshake response format");
                        return;
                    }
                    byte[] peerStaticPubBytes = Arrays.copyOfRange(response, firstDelimiter + 1, secondDelimiter);
                    byte[] peerEphPubBytes = Arrays.copyOfRange(response, secondDelimiter + 1, bytesRead);
                    if (peerStaticPubBytes.length != 32 || peerEphPubBytes.length != 32) {
                        System.out.println("Invalid key length: static=" + peerStaticPubBytes.length + ", ephemeral=" + peerEphPubBytes.length);
                        return;
                    }

                    X25519PublicKeyParameters peerStaticPub = new X25519PublicKeyParameters(peerStaticPubBytes, 0);
                    X25519PublicKeyParameters peerEphPub = new X25519PublicKeyParameters(peerEphPubBytes, 0);

                    byte[] salt = ByteBuffer.allocate(crypto.getStaticPubKey().length + peerStaticPubBytes.length)
                            .put(crypto.getStaticPubKey()).put(peerStaticPubBytes).array();
                    byte[] sessionKey = crypto.performKeyExchange(peerStaticPub, peerEphPub, ephemeralPriv, salt);
                    String peerId = bytesToHex(peerStaticPubBytes).substring(0, 16);
                    sessionKeys.put(peerId, sessionKey);
                    System.out.println("Session established with " + peerId);
                } else {
                    System.out.println("No response received from peer");
                }
            }
        } catch (Exception e) {
            System.out.println("Failed to connect to " + parts[0] + ":" + parts[1] + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void sendFile(String peerId, String filePath) throws Exception {
        if (!peers.containsKey(peerId)) {
            System.out.println("Unknown peer");
            return;
        }
        byte[] data;
        try (FileInputStream fis = new FileInputStream(filePath)) {
            data = fis.readAllBytes();
        }
        byte[] fileHash = MessageDigest.getInstance("SHA-256").digest(data);
        byte[] encrypted = crypto.encryptFile(data, sessionKeys.get(peerId));
        byte[] myId = Arrays.copyOf(crypto.getStaticPubKey(), 8);

        try (Socket s = new Socket(peers.get(peerId).y.getAddress(), peers.get(peerId).y.getPort());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write("FILE_DATA|".getBytes());
            baos.write(myId);
            baos.write(fileHash);
            baos.write("||".getBytes());
            baos.write(encrypted);
            out.write(baos.toByteArray());
            System.out.println("File sent.");
        }
    }

    public void requestFileList(String peerId) throws Exception {
        if (!peers.containsKey(peerId)) {
            System.out.println("Peer not found");
            return;
        }
        try (Socket s = new Socket(peers.get(peerId).y.getAddress(), peers.get(peerId).y.getPort());
             DataOutputStream out = new DataOutputStream(s.getOutputStream());
             DataInputStream in = new DataInputStream(s.getInputStream())) {
            out.write(("REQUEST_LIST|" + bytesToHex(crypto.getStaticPubKey()).substring(0, 16)).getBytes());
            byte[] response = new byte[4096];
            int bytesRead = in.read(response);
            if (bytesRead > 0) {
                String responseStr = new String(response, 0, bytesRead, StandardCharsets.UTF_8);
                if (responseStr.startsWith("FILE_LIST|")) {
                    String files = responseStr.substring("FILE_LIST|".length());
                    System.out.println("Shared files:");
                    for (String f : files.split(";")) {
                        System.out.println("- " + f);
                    }
                } else {
                    System.out.println("Failed to get file list: " + responseStr);
                }
            } else {
                System.out.println("No response received for file list request");
            }
        }
    }

    public void rotateKey() throws Exception {
        System.out.println("Rotating key...");
        this.crypto = new CryptoManager();
        sessionKeys.clear();
        System.out.println("Key rotation complete. Please restart Zeroconf if needed.");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java com.secureclient.SecureShareClient [name] [--port PORT]");
            System.exit(1);
        }

        int port = 8081;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--port") && i + 1 < args.length) {
                port = Integer.parseInt(args[i + 1]);
                break;
            }
        }

        SecureShareClient client = new SecureShareClient(args[0], port);
        System.out.println("Secure P2P client ready. Type 'help' for commands.");

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            while (true) {
                System.out.print("> ");
                String cmd = reader.readLine().trim();
                if (cmd.startsWith("connect")) {
                    client.connectToPeer(cmd.split(" ")[1]);
                } else if (cmd.startsWith("send")) {
                    String[] parts = cmd.split(" ");
                    client.sendFile(parts[1], parts[2]);
                } else if (cmd.startsWith("listfiles")) {
                    client.requestFileList(cmd.split(" ")[1]);
                } else if (cmd.equals("rotatekey")) {
                    client.rotateKey();
                } else if (cmd.equals("list")) {
                    System.out.println("Known peers:");
                    client.peers.keySet().forEach(pid -> System.out.println("- " + pid));
                } else if (cmd.equals("exit") || cmd.equals("quit")) {
                    System.out.println("Exiting.");
                    break;
                } else if (cmd.equals("help")) {
                    System.out.println("Commands:\n connect IP[:PORT]\n send PEER_ID FILE\n listfiles PEER_ID\n rotatekey\n list\n exit");
                } else {
                    System.out.println("Unknown command");
                }
            }
        }
    }
}