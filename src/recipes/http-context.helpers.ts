export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none" | "Strict" | "Lax" | "None";
  maxAge?: number;
  path?: string;
  domain?: string;
}

export function extractBearerToken(context: any): string | undefined {
  const header =
    context?.req?.headers?.authorization ??
    context?.request?.headers?.authorization ??
    context?.headers?.authorization;

  if (typeof header === "string" && header.toLowerCase().startsWith("bearer ")) {
    return header.slice(7);
  }

  return undefined;
}

export function setBearerToken(context: any, token: string): void {
  const value = `Bearer ${token}`;
  if (typeof context?.res?.setHeader === "function") {
    context.res.setHeader("Authorization", value);
  } else if (typeof context?.response?.setHeader === "function") {
    context.response.setHeader("Authorization", value);
  } else if (typeof context?.setHeader === "function") {
    context.setHeader("Authorization", value);
  }
}

export function getCookie(context: any, name: string): string | undefined {
  return (
    context?.req?.cookies?.[name] ??
    context?.request?.cookies?.[name] ??
    context?.cookies?.[name]
  );
}

export function setCookie(
  context: any,
  name: string,
  value: string,
  options: CookieOptions = {}
): void {
  if (typeof context?.res?.cookie === "function") {
    context.res.cookie(name, value, options);
  } else if (typeof context?.response?.cookie === "function") {
    context.response.cookie(name, value, options);
  } else if (typeof context?.cookie === "function") {
    context.cookie(name, value, options);
  }
}

export function redirect(context: any, url: string, status = 302): void {
  if (typeof context?.res?.redirect === "function") {
    context.res.redirect(url);
  } else if (typeof context?.response?.redirect === "function") {
    context.response.redirect(url);
  } else if (typeof context?.redirect === "function") {
    context.redirect(url);
  } else if (typeof context?.res?.setHeader === "function") {
    context.res.setHeader("Location", url);
    context.res.status?.(status);
  } else if (typeof context?.setHeader === "function") {
    context.setHeader("Location", url);
    context.status?.(status);
  }
}
