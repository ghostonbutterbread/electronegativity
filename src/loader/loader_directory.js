import fs from 'fs';
import { read_file, list_files } from '../util';
import { Loader } from './loader_interface';
import { findOldestElectronVersionWithSource } from "../util/electron_version";

export class LoaderDirectory extends Loader {
  constructor() {
    super();
  }

  async load(dir) {
    const files = await list_files(dir);

    for (const file of files) {
      this._loaded.add(file);
    }

    const readAndOptionallyParse = (filename, shouldParse) => {
      try {
        const file = files.find(f => f.endsWith(filename));
        if (!file) return undefined;
        if (!shouldParse) return this.load_buffer(file);
        return JSON.parse(this.load_buffer(file));
      } catch (e) {
        return undefined;
      }
    };

    const pjsonData = readAndOptionallyParse('package.json', true);
    const plockData = readAndOptionallyParse('package-lock.json', true);
    const yarnLockData = readAndOptionallyParse('yarn.lock', false);
    const electronVersion = await findOldestElectronVersionWithSource({
      pjsonData,
      rootPath: dir,
      plockData,
      yarnLockData,
    });
    if (electronVersion) {
      this._electronVersion = electronVersion.version;
      this._electronVersionSource = electronVersion.source;
    }
  }

  async stash() {
    this._loaded.clear();
  }

  load_buffer(filename) {
    const buffer = read_file(filename);
    return buffer;
  }

  file_exists(filename) {
    return fs.existsSync(filename);
  }
}
