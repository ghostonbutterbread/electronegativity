class ModernApi {
  #token = "secret";

  read(settings) {
    return settings?.bridge?.name ?? this.#token;
  }
}

export const api = new ModernApi();
import("./lazy").then(module => module.default(api));
