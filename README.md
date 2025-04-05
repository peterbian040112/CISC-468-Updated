# CISC-468-Updated
For the Python client, the user can start off with mkdir -p shared_files received_files signatures keys to create the necessary folder to keep everything tidy and accessable.
Or manually create these folders in the same path as the client. You can see the Java client in the Java branch.

Use python client.py [clientname] --port [portnumber] to launch the client

Command to use:
1. list: show all connected peers' IDs
2. connect [peer's IP and port number]: connect to a peer using its IP address and port number agreed upon on
3. request_list [peer's ID]: require the target peer to show its shared file list (without consent)
4. send [peer's ID]: sent file to the targeted 
5. request_download [peer's ID]: send download request to peer (need consent)
6. request_alt_download [Peer A's ID] [Peer C's ID]: use Peer C to retrieve A's list (if C has requested A's list)
7. update_keys: regenerate X25519 keys and notify other peers
8. verify_file [file_data] [signature] [pubkey]: verify file integrity

