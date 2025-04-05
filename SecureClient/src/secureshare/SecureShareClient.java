package secureshare;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

public class SecureShareClient {
    private final int port;
    private final String name;
    private final CryptoManager crypto;
    private final JmDNS jmdns;
    private final Map<String, PeerInfo> peers = new ConcurrentHashMap<>();
    private final Map<String, byte[]> sessionKeys = new ConcurrentHashMap<>();
    private volatile Tuple<String, String> pendingDownloadRequest;

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
        this.jmdns = JmDNS.create(InetAddress.getLocalHost());

        ServiceInfo serviceInfo = ServiceInfo.create(
            "_secure-share._tcp.local.",
            name,
            port,
            0,
            0,
            Map.of("pubkey", Base64.getEncoder().encodeToString(crypto.getStaticPubKey()))
        );
        jmdns.registerService(serviceInfo);

        jmdns.addServiceListener("_secure-share._tcp.local.", new ServiceListener() {
            @Override
            public void serviceAdded(ServiceEvent event) {
                ServiceInfo info = jmdns.getServiceInfo(event.getType(), event.getName());
                if (info != null) {
                    handleServiceAdded(info);
                }
            }

            @Override
            public void serviceRemoved(ServiceEvent event) {
                String peerId = bytesToHex(Arrays.copyOf(Base64.getDecoder().decode(event.getName().split("\\.")[0]), 8));
                peers.remove(peerId);
            }

            @Override
            public void serviceResolved(ServiceEvent event) {}
        });

        Thread serverThread = new Thread(this::startServer);
        serverThread.setDaemon(true);
        serverThread.start();
    }

    private void handleServiceAdded(ServiceInfo info) {
        String pubKeyStr = info.getPropertyString("pubkey");
        byte[] peerPubKey = Base64.getDecoder().decode(pubKeyStr);
        if (!Arrays.equals(peerPubKey, crypto.getStaticPubKey())) {
            String peerId = bytesToHex(Arrays.copyOf(peerPubKey, 8));
            peers.put(peerId, new PeerInfo(peerPubKey, info.getInet4Addresses()[0].getHostAddress(), info.getPort()));
            System.out.println("Discovered new peer: " + info.getName() + " at " + 
                             info.getInet4Addresses()[0].getHostAddress() + ":" + info.getPort());
        }
    }

    private void startServer() {
        try (ServerSocket server = new ServerSocket(port)) {
            InetAddress localAddr = getLocalIPv4Address();
            System.out.println("Server started on " + localAddr.getHostAddress() + ":" + port);
            while (true) {
                Socket client = server.accept();
                Thread clientThread = new Thread(() -> handleConnection(client));
                clientThread.start();
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
        }
    }

    private void handleConnection(Socket conn) {
        try {
            conn.setSoTimeout(100);
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int bytesRead;
            InputStream input = conn.getInputStream();
            while ((bytesRead = input.read(chunk)) != -1) {
                buffer.write(chunk, 0, bytesRead);
                try {
                    bytesRead = input.read(chunk);
                } catch (SocketTimeoutException e) {
                    break;
                }
            }
            byte[] data = buffer.toByteArray();
            System.out.println("Data received, length " + data.length + " bytes");

            String header = new String(Arrays.copyOfRange(data, 0, Math.min(20, data.length)));
            if (header.startsWith("HANDSHAKE")) {
                processHandshake(conn, data);
            } else if (header.startsWith("FILE_DATA")) {
                processFileData(conn, data);
            } else if (header.startsWith("LIST_FILES")) {
                processListFiles(conn, data);
            } else if (header.startsWith("DOWNLOAD_REQUEST")) {
                processDownloadRequest(conn, data);
            } else {
                System.out.println("Unknown request type: " + header);
            }
        } catch (Exception e) {
            System.err.println("Error processing connection: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                conn.close();
            } catch (IOException e) {
                System.err.println("Error closing connection: " + e.getMessage());
            }
        }
    }

    private void processHandshake(Socket conn, byte[] data) throws Exception {
        String[] parts = new String(data).split("\\|", 2);
        if (parts.length != 2) return;
    
        byte[] peerStaticPubBytes = Base64.getDecoder().decode(parts[1]);
        if (peerStaticPubBytes.length != 32) {
            throw new Exception("Invalid peer static public key length: " + peerStaticPubBytes.length);
        }
    
        X25519PublicKeyParameters peerStaticPub = new X25519PublicKeyParameters(peerStaticPubBytes, 0);
        X25519PrivateKeyParameters myStaticPriv = new X25519PrivateKeyParameters(crypto.getStaticPrivKey(), 0);
        
        byte[] sessionKey = crypto.performKeyExchange(peerStaticPub, myStaticPriv);
        String peerId = bytesToHex(Arrays.copyOf(peerStaticPubBytes, 8));
        sessionKeys.put(peerId, sessionKey);
        
        OutputStream output = conn.getOutputStream();
        output.write(("HANDSHAKE_OK|" + Base64.getEncoder().encodeToString(crypto.getStaticPubKey())).getBytes());
        
        System.out.println("Session established, peer ID: " + peerId);
    }

    private void processFileData(Socket conn, byte[] data) throws Exception {
        if (data.length < 10 || !new String(Arrays.copyOf(data, 10)).equals("FILE_DATA|")) {
            throw new Exception("Invalid FILE_DATA header");
        }
        int separatorIdx = indexOf(data, "|".getBytes(), 18);
        if (separatorIdx == -1) {
            throw new Exception("Invalid FILE_DATA format: No separator found after peer ID");
        }
        byte[] peerIdBytes = Arrays.copyOfRange(data, 10, 18);
        String peerId = bytesToHex(peerIdBytes);
        byte[] ciphertext = Arrays.copyOfRange(data, separatorIdx + 1, data.length);

        byte[] plaintext = null;
        if (sessionKeys.containsKey(peerId)) {
            plaintext = crypto.decryptFile(ciphertext, sessionKeys.get(peerId));
        } else {
            System.out.println("Unknown peer ID: " + peerId + "; saving file without decryption");
            plaintext = ciphertext;
        }

        File receivedDir = new File("received_files");
        receivedDir.mkdirs();
        String filename = peerId + "_" + System.currentTimeMillis() + ".bin";
        try (FileOutputStream fos = new FileOutputStream(new File(receivedDir, filename))) {
            fos.write(plaintext);
        }
        System.out.println("File saved as: " + filename + " from peer " + peerId);
    }

    private void processListFiles(Socket conn, byte[] data) throws Exception {
        byte[] peerIdBytes = Arrays.copyOfRange(data, 10, data.length);
        String peerId = bytesToHex(peerIdBytes);
        String fileList = String.join("\n", getSharedFiles());
        byte[] encryptedList = crypto.encryptFile(fileList.getBytes(), sessionKeys.get(peerId));
        conn.getOutputStream().write(("FILE_LIST|" + Base64.getEncoder().encodeToString(encryptedList)).getBytes());
    }

    private void processDownloadRequest(Socket conn, byte[] data) {
        String[] parts = new String(data).split("\\|");
        if (parts.length < 3) return;
        
        String peerId = bytesToHex(Base64.getDecoder().decode(parts[1]));
        String filename = parts[2];
        pendingDownloadRequest = new Tuple<>(peerId, filename);
        System.out.println("\nPlease confirm the download request: User " + peerId + 
                         " request to download a file " + filename);
        System.out.println("Type 'approve' to approve the download request, or 'reject' to reject the download request");
    }

    public void connectToPeer(String address) throws Exception {
        String[] parts = address.split(":");
        String ip = parts[0];
        int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 8080;
    
        try (Socket socket = new Socket(ip, port)) {
            socket.setSoTimeout(5000);
            OutputStream output = socket.getOutputStream();
            String handshake = "HANDSHAKE|" + Base64.getEncoder().encodeToString(crypto.getStaticPubKey());
            output.write(handshake.getBytes());
            output.flush();
    
            InputStream input = socket.getInputStream();
            ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            try {
                while ((bytesRead = input.read(buffer)) != -1) {
                    responseStream.write(buffer, 0, bytesRead);
                    if (responseStream.size() >= 78) break;
                }
            } catch (SocketTimeoutException e) {
                // Timeout occurred, use what we have
            }
            byte[] response = responseStream.toByteArray();
    
            if (new String(response).startsWith("HANDSHAKE_OK")) {
                String[] responseParts = new String(response).split("\\|", 2);
                if (responseParts.length != 2) {
                    throw new Exception("Invalid handshake response format");
                }
    
                byte[] peerStaticPubBytes = Base64.getDecoder().decode(responseParts[1]);
                if (peerStaticPubBytes.length != 32) {
                    throw new Exception("Invalid peer static public key length: " + peerStaticPubBytes.length);
                }
    
                X25519PublicKeyParameters peerStaticPub = new X25519PublicKeyParameters(peerStaticPubBytes, 0);
                X25519PrivateKeyParameters myStaticPriv = new X25519PrivateKeyParameters(crypto.getStaticPrivKey(), 0);
                
                byte[] sessionKey = crypto.performKeyExchange(peerStaticPub, myStaticPriv);
                String peerId = bytesToHex(Arrays.copyOf(peerStaticPubBytes, 8));
                sessionKeys.put(peerId, sessionKey);
    
                peers.put(peerId, new PeerInfo(peerStaticPub.getEncoded(), ip, port));
    
                System.out.println("Successfully connected to " + address);
                System.out.println("Peer ID " + peerId);
            } else {
                throw new Exception("Handshake failed: " + new String(response));
            }
        }
    }

    public void sendFile(String peerId, String filePath) throws Exception {
        if (!sessionKeys.containsKey(peerId)) return;

        byte[] data;
        try (FileInputStream fis = new FileInputStream(filePath)) {
            data = fis.readAllBytes();
        }
        byte[] encrypted = crypto.encryptFile(data, sessionKeys.get(peerId));
        byte[] myIdBytes = Arrays.copyOf(crypto.getStaticPubKey(), 8);

        try (Socket socket = new Socket(peers.get(peerId).address, peers.get(peerId).port)) {
            OutputStream output = socket.getOutputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write("FILE_DATA|".getBytes());
            baos.write(myIdBytes);
            baos.write("|".getBytes());
            baos.write(encrypted);
            byte[] sentData = baos.toByteArray();
            output.write(sentData);
            System.out.println("File sent to " + peerId);
        }
    }

    private List<String> getSharedFiles() {
        File sharedDir = new File("shared_files");
        sharedDir.mkdirs();
        return Arrays.asList(sharedDir.list((dir, name) -> new File(dir, name).isFile()));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static int indexOf(byte[] array, byte[] target, int start) {
        for (int i = start; i < array.length - target.length + 1; i++) {
            boolean found = true;
            for (int j = 0; j < target.length; j++) {
                if (array[i + j] != target[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return -1;
    }

    private static class PeerInfo {
        byte[] pubKey;
        String address;
        int port;

        PeerInfo(byte[] pubKey, String address, int port) {
            this.pubKey = pubKey;
            this.address = address;
            this.port = port;
        }
    }

    private static class Tuple<T1, T2> {
        T1 first;
        T2 second;

        Tuple(T1 first, T2 second) {
            this.first = first;
            this.second = second;
        }
    }

    private void printHelp() {
        System.out.println("Available commands:");
        System.out.println("  help                - Display this help message");
        System.out.println("  quit                - Exit the application");
        System.out.println("  list                - List all discovered peers");
        System.out.println("  connect <ip:port>   - Connect to a peer at the specified IP and port");
        System.out.println("  send <peerId> <file> - Send a file to a peer");
        System.out.println("  approve             - Approve a pending download request");
        System.out.println("  reject              - Reject a pending download request");
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java -cp \"bin;lib/*\" secureshare.SecureShareClient [name] [--port PORT]");
            System.exit(1);
        }

        int port = 8081;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--port") && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            }
        }

        SecureShareClient client = new SecureShareClient(args[0], port);
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.print("> ");
            String cmd = scanner.nextLine();
            try {
                if (cmd.equals("quit")) {
                    break;
                } else if (cmd.equals("list")) {
                    System.out.println("Discovered peers:");
                    client.peers.keySet().forEach(pid -> System.out.println("- " + pid));
                } else if (cmd.startsWith("connect")) {
                    client.connectToPeer(cmd.split(" ")[1]);
                } else if (cmd.startsWith("send")) {
                    String[] parts = cmd.split(" ");
                    client.sendFile(parts[1], parts[2]);
                } else if (cmd.equals("approve") && client.pendingDownloadRequest != null) {
                    client.sendFile(client.pendingDownloadRequest.first, 
                                  "shared_files/" + client.pendingDownloadRequest.second);
                    client.pendingDownloadRequest = null;
                } else if (cmd.equals("reject") && client.pendingDownloadRequest != null) {
                    client.pendingDownloadRequest = null;
                    System.out.println("Download request rejected");
                } else if (cmd.equals("help")) {
                    client.printHelp();
                } else {
                    System.out.println("Unknown command. Type 'help' for a list of commands.");
                }
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
            }
        }
        scanner.close();
        client.jmdns.close();
    }
}