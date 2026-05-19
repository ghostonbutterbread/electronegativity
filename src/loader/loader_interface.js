export class Loader {
  constructor() {
    this._loaded = new Set();
    this._electronVersion = undefined;
    this._electronVersionSource = undefined;
  }

  get list_files() { return this._loaded; }
  get electronVersion() { return this._electronVersion; }
  get electronVersionSource() { return this._electronVersionSource; }

  // eslint-disable-next-line no-unused-vars
  load_buffer(filename) {
    return undefined;
  }

  file_exists(filename) {
    return this._loaded.has(filename);
  }
}
