import type { MediaUnderstandingCapability } from "../media-understanding/types.js";
import { normalizeExtensionHostMediaProviderId } from "./media-runtime-registry.js";
import {
  listExtensionHostMediaAutoRuntimeBackendIds,
  resolveExtensionHostMediaRuntimeDefaultModel,
} from "./runtime-backend-catalog.js";

export type ExtensionHostMediaActiveModel = {
  provider: string;
  model?: string;
};

export type ExtensionHostMediaProviderCandidate = {
  provider: string;
  model?: string;
};

function resolveExtensionHostMediaCandidateModel(params: {
  capability: MediaUnderstandingCapability;
  provider: string;
  activeModel?: ExtensionHostMediaActiveModel;
}): string | undefined {
  const activeProvider = params.activeModel?.provider?.trim();
  if (
    activeProvider &&
    normalizeExtensionHostMediaProviderId(activeProvider) ===
      normalizeExtensionHostMediaProviderId(params.provider)
  ) {
    return params.activeModel?.model;
  }
  return resolveExtensionHostMediaRuntimeDefaultModel({
    capability: params.capability,
    backendId: params.provider,
  });
}

export function resolveExtensionHostMediaProviderCandidates(params: {
  capability: MediaUnderstandingCapability;
  activeModel?: ExtensionHostMediaActiveModel;
}): readonly ExtensionHostMediaProviderCandidate[] {
  const candidates: ExtensionHostMediaProviderCandidate[] = [];
  const seen = new Set<string>();

  const pushCandidate = (provider: string | undefined): void => {
    const normalized = provider?.trim()
      ? normalizeExtensionHostMediaProviderId(provider)
      : undefined;
    if (!normalized || seen.has(normalized)) {
      return;
    }
    seen.add(normalized);
    candidates.push({
      provider: normalized,
      model: resolveExtensionHostMediaCandidateModel({
        capability: params.capability,
        provider: normalized,
        activeModel: params.activeModel,
      }),
    });
  };

  pushCandidate(params.activeModel?.provider);
  for (const providerId of listExtensionHostMediaAutoRuntimeBackendIds(params.capability)) {
    pushCandidate(providerId);
  }

  return candidates;
}
