export const EXPLICIT_DEV_RENDERER_URL = "http://127.0.0.1:4317/";

export type RendererTarget =
  | { readonly kind: "bundle"; readonly url: "app://bundle/index.html" }
  | {
      readonly kind: "dev-server";
      readonly url: typeof EXPLICIT_DEV_RENDERER_URL;
    };

/**
 * Unpackaged builds still use the built local bundle by default. A development
 * server is selected only by the one exact allowlisted environment value.
 */
export function selectRendererTarget(
  isPackaged: boolean,
  requestedDevUrl: string | undefined,
): RendererTarget {
  if (
    !isPackaged &&
    requestedDevUrl === EXPLICIT_DEV_RENDERER_URL
  ) {
    return {
      kind: "dev-server",
      url: EXPLICIT_DEV_RENDERER_URL,
    };
  }
  return {
    kind: "bundle",
    url: "app://bundle/index.html",
  };
}
