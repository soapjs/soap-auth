import { JwtTools } from "./jwt.tools";
import { TokenConfig } from "./types";

export class JwtRegistry {
  private list: Map<string, JwtTools> = new Map<string, JwtTools>();

  add(name: string, config: TokenConfig) {
    this.list.set(name, new JwtTools(config));
  }

  get(name: string) {
    return this.list.get(name);
  }
}
