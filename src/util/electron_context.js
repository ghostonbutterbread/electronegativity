import { gte, minVersion } from 'semver';

// These thresholds drive Phase 3's version-aware omission handling. They extend
// the legacy snapshots in defaults.json, which Finder still uses for older check
// behavior, so changes here should be covered by tests when Electron defaults move.
const DEFAULT_BEHAVIOR_THRESHOLDS = {
  nodeIntegration: { version: '5.0.0', before: true, after: false },
  contextIsolation: { version: '12.0.0', before: false, after: true },
  sandbox: { version: '20.0.0', before: false, after: true }
};

const SECURE_SETTING_VALUES = {
  nodeIntegration: false,
  contextIsolation: true,
  sandbox: true
};

function normalizeVersion(version) {
  if (!version)
    return null;

  try {
    const parsed = minVersion(version);
    return parsed ? parsed.version : null;
  } catch (_) {
    return null;
  }
}

function normalizeFuseMap(fuses) {
  return Object.keys(fuses || {}).sort().reduce((result, key) => {
    result[key] = fuses[key];
    return result;
  }, {});
}

function settingKey(setting) {
  return setting.replace(/([A-Z])/g, '_$1').toLowerCase();
}

export function createVersionContext(options = {}) {
  const electronVersion = normalizeVersion(options.electronVersion || options.electronVersionOverride);
  const source = options.electronVersionOverride ? 'cli' : (electronVersion ? (options.electronVersionSource || 'unknown') : 'unknown');
  let confidence = 'low';

  if (source === 'cli')
    confidence = 'high';
  else if (source === 'package_json' || source === 'lockfile')
    confidence = 'medium';

  return {
    electronVersion,
    source,
    confidence,
    known: Boolean(electronVersion)
  };
}

export function normalizeVersionContext(value, options = {}) {
  if (value && typeof value === 'object' && !Array.isArray(value) &&
      (Object.prototype.hasOwnProperty.call(value, 'electronVersion') ||
       Object.prototype.hasOwnProperty.call(value, 'source') ||
       Object.prototype.hasOwnProperty.call(value, 'confidence') ||
       Object.prototype.hasOwnProperty.call(value, 'known'))) {
    return createVersionContext({
      electronVersion: value.electronVersion,
      electronVersionSource: value.source,
      electronVersionOverride: value.source === 'cli' ? value.electronVersion : null
    });
  }

  return createVersionContext(Object.assign({}, options, { electronVersion: value }));
}

export function createFuseContext(value = null) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const wrapperKeys = new Set(['state', 'source', 'fuses']);
    const rawFuseMap = Object.keys(value).some(key => !wrapperKeys.has(key));
    const fuses = normalizeFuseMap(rawFuseMap ? value : (value.fuses || {}));
    const state = value.state || (Object.keys(fuses).length > 0 ? 'known' : 'unknown');

    return {
      state,
      source: value.source || (state === 'known' ? 'explicit' : 'unknown'),
      fuses
    };
  }

  return {
    state: 'unknown',
    source: 'unknown',
    fuses: {}
  };
}

export function normalizeFuseContext(value) {
  return createFuseContext(value);
}

export function defaultBehaviorForSetting(setting, versionContext) {
  const context = normalizeVersionContext(versionContext);
  const threshold = DEFAULT_BEHAVIOR_THRESHOLDS[setting];
  const key = settingKey(setting);

  if (!threshold)
    return {
      setting,
      known: false,
      value: null,
      behavior: `${key}_default_unknown`
    };

  if (!context.known) {
    return {
      setting,
      known: false,
      value: null,
      behavior: `${key}_default_unknown`
    };
  }

  const value = gte(context.electronVersion, threshold.version) ? threshold.after : threshold.before;
  return {
    setting,
    known: true,
    value,
    behavior: `${key}_default_${value ? 'true' : 'false'}`
  };
}

export function buildCheckVersionContext(setting, versionContext) {
  const context = normalizeVersionContext(versionContext);
  const defaultBehavior = defaultBehaviorForSetting(setting, context);

  return {
    electronVersion: context.electronVersion,
    electronVersionSource: context.source,
    electronVersionConfidence: context.confidence,
    defaultBehavior: defaultBehavior.behavior
  };
}

export function issueClassificationForDefaultBehavior(setting, defaultBehavior) {
  if (!defaultBehavior || !defaultBehavior.known)
    return 'finding';

  if (!Object.prototype.hasOwnProperty.call(SECURE_SETTING_VALUES, setting))
    return 'finding';

  return defaultBehavior.value === SECURE_SETTING_VALUES[setting] ? 'hardening' : 'finding';
}

export function buildIssueProperties(options = {}) {
  const properties = Object.assign({}, options.properties || {});

  properties.issueType = options.issueType || properties.issueType || 'finding';
  properties.issueClassification = options.issueClassification || properties.issueClassification || 'finding';

  if (Object.prototype.hasOwnProperty.call(options, 'versionContext'))
    properties.versionContext = options.versionContext;

  return properties;
}

export function buildCheckProperties(setting, versionContext, options = {}) {
  return buildIssueProperties({
    properties: options.properties,
    issueType: options.issueType,
    issueClassification: options.issueClassification,
    versionContext: buildCheckVersionContext(setting, versionContext)
  });
}
