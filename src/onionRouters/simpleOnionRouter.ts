import bodyParser from "body-parser";
import express from "express";
import axios from "axios";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { 
  generateRsaKeyPair, 
  exportPubKey, 
  exportPrvKey,
  importPrvKey,
  rsaDecrypt,
  symDecrypt
} from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
    const onionRouter = express();
    onionRouter.use(express.json());
    onionRouter.use(bodyParser.json());

    const nodeStorage = {
        nodes: new Map(),
        setLastReceivedEncryptedMessage(nodeId: number, message: string): void {
            const nodeData = this.nodes.get(nodeId) || {};
            nodeData.lastReceivedEncryptedMessage = message;
            this.nodes.set(nodeId, nodeData);
        },
        getLastReceivedEncryptedMessage(nodeId: number): string | null {
            const nodeData = this.nodes.get(nodeId) || {};
            return nodeData.lastReceivedEncryptedMessage || null;
        },
        setLastReceivedDecryptedMessage(nodeId: number, message: string): void {
            const nodeData = this.nodes.get(nodeId) || {};
            nodeData.lastReceivedDecryptedMessage = message;
            this.nodes.set(nodeId, nodeData);
        },
        getLastReceivedDecryptedMessage(nodeId: number): string | void {
            const nodeData = this.nodes.get(nodeId) || {};
            return nodeData.lastReceivedDecryptedMessage || null;
        },
        setLastMessageDestination(nodeId: number, destination: string): void {
            const nodeData = this.nodes.get(nodeId) || {};
            nodeData.lastMessageDestination = destination;
            this.nodes.set(nodeId, nodeData);
        },
        getLastMessageDestination(nodeId: number): string | void {
            const nodeData = this.nodes.get(nodeId) || {};
            return nodeData.lastMessageDestination || null;
        }
    };

    // Status route
    onionRouter.get("/status", (req, res) => {
        res.send("live");
    });

    // Routes for getting last message information
    onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
        const result = nodeStorage.getLastReceivedEncryptedMessage(nodeId) || null;
        res.json({ result });
    });

    onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
        const result = nodeStorage.getLastReceivedDecryptedMessage(nodeId) || null;
        res.json({ result });
    });

    onionRouter.get("/getLastMessageDestination", (req, res) => {
        const result = nodeStorage.getLastMessageDestination(nodeId) || null;
        res.json({ result });
    });

    // Generate RSA key pair for this node
    const keyPair = await generateRsaKeyPair();
    const publicKey = await exportPubKey(keyPair.publicKey);
    const privateKey = await exportPrvKey(keyPair.privateKey);
    
    // Store keys in node storage
    nodeStorage.nodes.set(nodeId, {
        ...nodeStorage.nodes.get(nodeId) || {},
        publicKey,
        privateKey,
        cryptoKeys: keyPair // Store the actual CryptoKey objects for later use
    });

    // Route to get private key (for testing purposes)
    onionRouter.get("/getPrivateKey", (req, res) => {
        const nodeData = nodeStorage.nodes.get(nodeId) || {};
        res.json({ result: nodeData.privateKey || null });
    });

    // Route to receive and forward messages
    onionRouter.post("/message", async (req, res) => {
        try {
            const { message } = req.body;
            
            // Save the encrypted message
            nodeStorage.setLastReceivedEncryptedMessage(nodeId, message);
            
            // Get the node's private key
            const nodeData = nodeStorage.nodes.get(nodeId) || {};
            const privateKeyStr = nodeData.privateKey;
            
            if (!privateKeyStr) {
                throw new Error("Private key not found");
            }
            
            // Import the private key
            const privateKey = await importPrvKey(privateKeyStr);
            
            // The message format is: [encrypted symmetric key][encrypted data]
            // First, identify where the encrypted symmetric key ends
            // For RSA-2048, the encrypted symmetric key should be fixed length
            
            // Split the message - RSA-2048 encrypted data is roughly 344 characters in base64
            // This is an approximation - in production code, use a delimiter
            const encryptedSymKey = message.substring(0, 344); 
            const encryptedData = message.substring(344);
            
            // Decrypt the symmetric key
            const symmetricKeyStr = await rsaDecrypt(encryptedSymKey, privateKey);
            
            // Decrypt the data using the symmetric key
            const decryptedData = await symDecrypt(symmetricKeyStr, encryptedData);
            
            // Save the decrypted message
            nodeStorage.setLastReceivedDecryptedMessage(nodeId, decryptedData);
            
            // Extract the destination from the first 10 characters
            const destinationPort = parseInt(decryptedData.substring(0, 10));
            nodeStorage.setLastMessageDestination(nodeId, destinationPort.toString());
            
            // Extract the actual message content (remove the 10-char destination)
            const messageContent = decryptedData.substring(10);
            
            // Forward the message to the next destination
            await axios.post(`http://localhost:${destinationPort}/message`, {
                message: messageContent
            });
            
            res.status(200).json({ status: "Message forwarded successfully" });
        } catch (error) {
            console.error(`Error processing message at node ${nodeId}:`, error);
            res.status(500).json({ error: "Failed to process message" });
        }
    });

    const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, async () => {
        console.log(
            `Onion router ${nodeId} is listening on port ${
                BASE_ONION_ROUTER_PORT + nodeId
            }`
        );
        
        // Register with the registry after starting up
        try {
            await axios.post(`http://localhost:${REGISTRY_PORT}/registerNode`, {
                nodeId,
                pubKey: publicKey
            });
            console.log(`Node ${nodeId} registered successfully with the registry`);
        } catch (error) {
            console.error(`Failed to register node ${nodeId} with registry:`, error);
        }
    });
    
    return server;
}