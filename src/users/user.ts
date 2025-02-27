import bodyParser from "body-parser";
import express from "express";
import axios from "axios";
import { BASE_USER_PORT, BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { 
  createRandomSymmetricKey,
  exportSymKey,
  rsaEncrypt,
  symEncrypt 
} from "../crypto";

export type SendMessageBody = {
    message: string;
    destinationUserId: number;
};

export async function user(userId: number) {
    const _user = express();
    _user.use(express.json());
    _user.use(bodyParser.json());
    
    // Store for user messages with explicit typing
    let lastReceivedMessage: string | null = null;
    let lastSentMessage: string | null = null;
    
    // Store the last circuit used
    let lastCircuit: number[] = [];
    
    // Status route
    _user.get("/status", (req, res) => {
        res.send("live");
    });
    
    // Route to get last received message
    _user.get("/getLastReceivedMessage", (req, res) => {
        res.json({ result: lastReceivedMessage });
    });
    
    // Route to get last sent message
    _user.get("/getLastSentMessage", (req, res) => {
        res.json({ result: lastSentMessage });
    });
    
    // Route to get the last circuit
    _user.get("/getLastCircuit", (req, res) => {
        res.json({ result: lastCircuit });
    });
    
    // Route to receive messages
    _user.post("/message", (req, res) => {
        const { message } = req.body;
        lastReceivedMessage = message;
        res.send("success");
    });
    
    // Route to send messages through the onion network
    _user.post("/sendMessage", async (req, res) => {
        try {
            const { message, destinationUserId } = req.body;
            lastSentMessage = message;
            
            // 1. Get the node registry to build a circuit
            const registryResponse = await axios.get(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
            const nodes = registryResponse.data.nodes;
            
            if (nodes.length < 3) {
                throw new Error("Not enough nodes in the registry to create a circuit");
            }
            
            // 2. Select 3 random distinct nodes for the circuit
            const shuffledNodes = [...nodes].sort(() => 0.5 - Math.random());
            const circuit = shuffledNodes.slice(0, 3);
            
            // Store the circuit for later retrieval
            lastCircuit = circuit.map(node => node.nodeId);
            
            // 3. Calculate the destination user port
            const destinationPort = BASE_USER_PORT + destinationUserId;
            
            // 4. Create layers of encryption (working from exit node backward to entry node)
            
            // 4.1 For each node in the circuit, create a symmetric key
            const symKeys = await Promise.all([
                createRandomSymmetricKey(),
                createRandomSymmetricKey(),
                createRandomSymmetricKey()
            ]);
            
            // 4.2 Exit node (Layer 3): Destination is the final user
            let destinationStr = destinationPort.toString().padStart(10, '0');
            let currentMessage = destinationStr + message;
            
            // Encrypt with the exit node's symmetric key
            let encryptedData = await symEncrypt(symKeys[2], currentMessage);
            
            // Encrypt the symmetric key with the exit node's public key
            const exitNodePubKey = circuit[2].pubKey;
            const encryptedSymKey = await rsaEncrypt(
                await exportSymKey(symKeys[2]), 
                exitNodePubKey
            );
            
            // Combine the encrypted symmetric key and the encrypted message
            currentMessage = encryptedSymKey + encryptedData;
            
            // 4.3 Middle node (Layer 2): Destination is the exit node
            destinationStr = (BASE_ONION_ROUTER_PORT + circuit[2].nodeId).toString().padStart(10, '0');
            currentMessage = destinationStr + currentMessage;
            
            // Encrypt with the middle node's symmetric key
            encryptedData = await symEncrypt(symKeys[1], currentMessage);
            
            // Encrypt the symmetric key with the middle node's public key
            const middleNodePubKey = circuit[1].pubKey;
            const encryptedSymKey2 = await rsaEncrypt(
                await exportSymKey(symKeys[1]),
                middleNodePubKey
            );
            
            // Combine the encrypted symmetric key and the encrypted message
            currentMessage = encryptedSymKey2 + encryptedData;
            
            // 4.4 Entry node (Layer 1): Destination is the middle node
            destinationStr = (BASE_ONION_ROUTER_PORT + circuit[1].nodeId).toString().padStart(10, '0');
            currentMessage = destinationStr + currentMessage;
            
            // Encrypt with the entry node's symmetric key
            encryptedData = await symEncrypt(symKeys[0], currentMessage);
            
            // Encrypt the symmetric key with the entry node's public key
            const entryNodePubKey = circuit[0].pubKey;
            const encryptedSymKey3 = await rsaEncrypt(
                await exportSymKey(symKeys[0]),
                entryNodePubKey
            );
            
            // Create the final layered message
            const finalMessage = encryptedSymKey3 + encryptedData;
            
            // 5. Send the message to the entry node
            await axios.post(
                `http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0].nodeId}/message`,
                { message: finalMessage }
            );
            
            res.status(200).json({ status: "Message sent successfully" });
        } catch (error) {
            console.error("Error sending message:", error);
            res.status(500).json({ error: "Failed to send message" });
        }
    });
    
    const server = _user.listen(BASE_USER_PORT + userId, () => {
        console.log(
            `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
        );
    });
    
    return server;
}