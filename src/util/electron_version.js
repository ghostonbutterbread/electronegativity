import arb from "read-package-tree";
import { compare, minVersion } from 'semver';
import * as lockfile from '@yarnpkg/lockfile';

export function minMatchingVersion(versionString) {
  try {
    const v = minVersion(versionString);
    return v.raw;
  } catch (_) {
    return undefined;
  }
}

// As we cannot know which of potentially multiple Electron versions is actually in use, we always assume the oldest one just in case.
export function oldestVersion(versions) {
  const sortedVersions = (versions || []).sort((a, b) => compare(a, b));
  return sortedVersions.length > 0 ? minMatchingVersion(sortedVersions[0]) : undefined;
}

function sourceRank(source) {
  switch (source) {
    case 'package_json':
      return 0;
    case 'lockfile':
      return 1;
    case 'installed_package':
      return 2;
    default:
      return 3;
  }
}

function oldestVersionWithSource(candidates) {
  candidates = (candidates || []).filter(candidate => candidate && candidate.version);
  candidates.sort((a, b) => {
    const versionCompare = compare(a.version, b.version);
    if (versionCompare !== 0)
      return versionCompare;

    return sourceRank(a.source) - sourceRank(b.source);
  });
  return candidates.length > 0 ? candidates[0] : undefined;
}

export function findElectronVersionFromPackageJson(pjsonData) {
  const dependencies = Object.assign({}, pjsonData.devDependencies, pjsonData.dependencies);
  return minMatchingVersion(dependencies.electron);
}

export async function findElectronVersionsFromInstalledPackages(rootPath) {
  const packages = await arb(rootPath);
  return packages.children.filter((c) => c.name === 'electron').map((e) => minMatchingVersion(e.package.version));
}

export function findElectronVersionsFromPackageLock(plockData) {
  if (!plockData.dependencies) return undefined;
  // TODO: This currently only consideres the top-level dependencies.
  return Object.entries(plockData.dependencies).filter(d => d[0] === 'electron').map(d => minMatchingVersion(d[1].version));
}

export function findElectronVersionsFromYarnLock(yarnLockData) {
  // Converts the yarn.lock into the same format as package-lock.json.
  const plockData = lockfile.parse(yarnLockData);
  return findElectronVersionsFromPackageLock(plockData);
}

/**
 * Returns the oldest Electron version found in the given places.
 *
 * @param {Object} places The places to scan for Electron versions, may contain the following options:
 * @param {Object} [places.pjsonData] The data from the package.json file.
 * @param {string} [places.rootPath] The path to the module (will then scan the installed packages).
 * @param {Object} [places.plockData] The data from the package-lock.json file.
 * @param {string} [places.yarnLockData] The data from the yarn.lock file.
 *
 * @returns {string} The oldest version found.
 */
export async function findOldestElectronVersionWithSource(places) {
  let candidates = [];

  if (places.pjsonData) {
    const pjsonVersion = findElectronVersionFromPackageJson(places.pjsonData);
    if (pjsonVersion) candidates.push({ version: pjsonVersion, source: 'package_json' });
  }

  if (places.rootPath) {
    const installedVersions = await findElectronVersionsFromInstalledPackages(places.rootPath);
    if (installedVersions) candidates.push(...installedVersions.map(version => ({ version, source: 'installed_package' })));
  }

  if (places.plockData) {
    const plockVersions = findElectronVersionsFromPackageLock(places.plockData);
    if (plockVersions) candidates.push(...plockVersions.map(version => ({ version, source: 'lockfile' })));
  }

  if (places.yarnLockData) {
    const yarnLockVersions = findElectronVersionsFromYarnLock(places.yarnLockData);
    if (yarnLockVersions) candidates.push(...yarnLockVersions.map(version => ({ version, source: 'lockfile' })));
  }

  return oldestVersionWithSource(candidates);
}

export async function findOldestElectronVersion(places) {
  const result = await findOldestElectronVersionWithSource(places);
  return result ? result.version : undefined;
}
