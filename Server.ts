import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import express from "express";
import { createServer } from "./Tools.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
//import { requireBearerAuth } from "./auth/CustomBearerMiddleware.js";
import { EntraIdServerAuthProvider } from "./auth/EntraIdServerAuthProvider.js";
import getRawBody from "raw-body";
import { entraIdAuthRouter } from "./auth/EntraIdAuthRouter.js";
import { Request, Response, NextFunction } from "express";

const app = express();

const { server, cleanup } = createServer();
const provider = new EntraIdServerAuthProvider();

let transport: SSEServerTransport;

app.get("/sse", requireBearerAuth({
  provider,
  requiredScopes: ["User.Read"]
}), async (req, res) => {
  console.log("Received connection");
  transport = new SSEServerTransport("/message", res);
  await server.connect(transport);

  server.onclose = async () => {
    await cleanup();
    await server.close();
    process.exit(0);
  };
});

app.post("/message", requireBearerAuth({
  provider,
  requiredScopes: ["User.Read"]
}), async (req, res) => {
  console.log("Received message");

  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];

  const rawBody = await getRawBody(req, {
    limit: '1mb',
    encoding: 'utf-8'
  });

  const messageBody = JSON.parse(rawBody.toString());
  if (!messageBody.params) {
    messageBody.params = {};
  }
  messageBody.params.context = { token };

  await transport.handlePostMessage(req, res, messageBody);
});

app.get(
  "/auth/callback", 
  (req: Request, res: Response, next: NextFunction): void => {
    const { code, state } = req.query;
    
    if (!code || !state || Array.isArray(code) || Array.isArray(state)) {
      res.status(400).send("Invalid request parameters");
      return;
    }
    
    provider.handleCallback(code as string, state as string)
      .then((result) => {
        if (result.success) {
          res.redirect(result.redirectUrl);
        } else {
          res.status(400).send(result.error || "Unknown error");
        }
      })
      .catch((error) => {
        console.error("Error in callback handler:", error);
        res.status(500).send("Server error during authentication callback");
        next(error);
      });
  }
);

app.use(entraIdAuthRouter({
  provider: provider,
  issuerUrl: new URL('http://localhost:3001'),
  serviceDocumentationUrl: new URL('https://den.dev'),
  authorizationOptions: {},
  tokenOptions: {}
}));

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Server error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'production' ? undefined : err.message
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
