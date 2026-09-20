import { expect, it, vi } from "vitest";
import { createProviderApiKeyAuthMethod } from "./provider-api-key-auth.js";

it("exposes the native setup definition lazily without prompting, credentials or existing account state", () => {
  const applyConfig = vi.fn(() => ({
    models: {
      providers: {
        regional: {
          baseUrl: "https://api.example.cn/anthropic",
          models: [],
        },
      },
    },
  }));
  const method = createProviderApiKeyAuthMethod({
    providerId: "regional",
    methodId: "api-cn",
    label: "China API key",
    optionKey: "regionalApiKey",
    flagName: "--regional-api-key",
    envVar: "REGIONAL_API_KEY",
    promptMessage: "Enter key",
    applyConfig,
  });
  expect(applyConfig).not.toHaveBeenCalled();
  expect(method.managedApiKey?.providerConfig()).toEqual({
    baseUrl: "https://api.example.cn/anthropic",
    models: [],
  });
  expect(applyConfig).toHaveBeenCalledWith({});
});
