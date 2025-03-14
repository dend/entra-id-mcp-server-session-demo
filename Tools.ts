import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
  ToolSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { ConfidentialClientApplication } from "@azure/msal-node";
import { Client } from "@microsoft/microsoft-graph-client";
import 'isomorphic-fetch';
import dotenv from 'dotenv';
import { tokenStore } from "./auth/TokenStore.js";

dotenv.config();

const requiredEnvVars = ['FR_API_CLIENT_ID', 'FR_API_CLIENT_SECRET', 'FR_TENANT_ID'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
  throw new Error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
}

const msalConfig = {
  auth: {
    clientId: process.env.FR_API_CLIENT_ID!,
    clientSecret: process.env.FR_API_CLIENT_SECRET!,
    authority: `https://login.microsoftonline.com/${process.env.FR_TENANT_ID}`
  }
};
const confidentialClient = new ConfidentialClientApplication(msalConfig);

type ToolInput = z.infer<typeof ToolSchema.shape.inputSchema>;

const ListSubscriptionsSchema = z.object({});

enum ToolName {
  GET_USER_DETAILS = "getUserDetails",
}

export const createServer = () => {
  const server = new Server(
    {
      name: "simple-mcp-server",
      version: "0.0.1",
    },
    {
      capabilities: {
        prompts: {},
        resources: { subscribe: true },
        tools: {},
        logging: {},
      },
    },
  );

  let updateInterval: NodeJS.Timeout | undefined;

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools: Tool[] = [
      {
        name: ToolName.GET_USER_DETAILS,
        description: "A tool that can provide details about the currently authenticated user.",
        inputSchema: zodToJsonSchema(ListSubscriptionsSchema) as ToolInput,
      }
    ];

    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name } = request.params;
    const context = request.params?.context as { token?: string } | undefined;
    const sessionToken = context?.token;

    if (name === ToolName.GET_USER_DETAILS) {
      try {
        if (!sessionToken) {
          throw new Error("No authentication token provided");
        }

        const tokenData = tokenStore.getToken(sessionToken);
        if (!tokenData) {
          throw new Error("Invalid or expired session token");
        }

        const entraIdToken = tokenData.accessToken;

        const graphClient = Client.init({
          authProvider: (done) => {
            done(null, entraIdToken);
          }
        });

        const user = await graphClient
          .api('/me')
          .select('displayName,mail,userPrincipalName')
          .get();

        return {
          content: [
            {
              type: "text",
              text: `User Details:
                Name: ${user.displayName}
                Email: ${user.mail}
                UPN: ${user.userPrincipalName}`,
            },
          ],
        };

      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: "text",
              text: `Error getting user details: ${errorMessage}`,
            },
          ],
        };
      }
    }

    throw new Error(`Unknown tool: ${name}`);
  });

  const cleanup = async () => {
    if (updateInterval) {
      clearInterval(updateInterval);
    }
  };

  return { server, cleanup };
};
