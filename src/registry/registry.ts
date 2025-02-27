import express, { Request, Response } from 'express';
import { REGISTRY_PORT } from '../config';

export type Node = { nodeId: number; pubKey: string };

// Define the GetNodeRegistryBody type that the test is looking for
export type GetNodeRegistryBody = {
  nodes: Node[];
};

// Memory storage for registered nodes
const nodes: Node[] = [];

export async function launchRegistry() {
  const app = express();
  app.use(express.json());

  // Route to check the registry's status
  app.get('/status', (req: Request, res: Response) => {
      res.send("live");
  });

  // Route to register a new node
  app.post('/registerNode', (req: Request, res: Response) => {
      const { nodeId, pubKey } = req.body;
      const node: Node = { nodeId, pubKey };
      nodes.push(node);
      res.status(201).json({ message: 'Node registered successfully', node });
  });

  // Route to get all registered nodes
  app.get('/getNodeRegistry', (req: Request, res: Response) => {
      const response: GetNodeRegistryBody = { nodes };
      res.status(200).json(response);
  });

  const server = app.listen(REGISTRY_PORT, () => {
      console.log(`Registry server listening on port ${REGISTRY_PORT}`);
  });

  return server;
}