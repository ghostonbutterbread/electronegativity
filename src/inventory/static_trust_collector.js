import crypto from 'crypto';

import { severity, confidence } from '../finder';
import { sourceTypes } from '../parser/types';
import { isDisabledByInlineComment } from '../util/exceptions';

const PHASE7_FINDING_IDS = new Set([
  'NAVIGATION_ALLOW_ALL',
  'WINDOW_OPEN_ALLOW_ALL',
  'OPEN_EXTERNAL_UNVALIDATED_URL',
  'OPEN_EXTERNAL_IN_WINDOW_HANDLER_UNVALIDATED',
  'FILE_PROTOCOL_APP_CONTENT_INVENTORY',
  'CUSTOM_PROTOCOL_BYPASS_CSP',
  'CUSTOM_PROTOCOL_FILE_PATH_TRAVERSAL_RISK',
  'CUSTOM_PROTOCOL_RISKY_PRIVILEGE_COMBINATION',
  'CUSTOM_PROTOCOL_MISSING_SECURE_STANDARD_FLAGS',
  'PERMISSION_HANDLER_MISSING_FOR_REMOTE_CONTENT',
  'PERMISSION_HANDLER_ALLOW_ALL',
  'PERMISSION_HANDLER_NO_ORIGIN_CHECK',
  'CSP_UNSAFE_INLINE',
  'CSP_UNSAFE_EVAL',
  'CSP_SCRIPT_SRC_WILDCARD',
  'CSP_WEAK_FOR_RENDERER_XSS'
]);

const PHASE8_FINDING_IDS = new Set([
  'RENDERER_POTENTIAL_XSS_SINK',
  'RENDERER_SANITIZER_WEAK_OR_UNKNOWN'
]);

const FINDING_IDS = new Set(Array.from(PHASE7_FINDING_IDS).concat(Array.from(PHASE8_FINDING_IDS)));

const SENSITIVE_PERMISSIONS = [
  'media',
  'geolocation',
  'notifications',
  'clipboard',
  'display-capture',
  'midi',
  'fullscreen',
  'openExternal'
];

const SOURCE_VECTOR_RULES = [
  { label: 'file_upload_import', pattern: /(?:upload|import|drop|drag)[A-Za-z0-9_$-]*(?:file|blob)|(?:file|blob)[A-Za-z0-9_$-]*(?:upload|import|drop|drag)|\bFileReader\b|\binput\s*\.\s*files\b/i },
  { label: 'export_preview', pattern: /\b(?:preview|renderPreview|thumbnail|export(?:Preview|Html|HTML|Image|Svg|SVG|Pdf|PDF|File|Blob|Data|Document|Canvas|Result)|exported(?:Html|HTML|Image|Svg|SVG|Pdf|PDF|File|Blob|Data|Document|Canvas))\b/i },
  { label: 'pasted_content', pattern: /(paste|clipboard|onpaste)/i },
  { label: 'comments_collaboration', pattern: /(comment|collab|mention|presence|message|chat)/i },
  { label: 'templates_assets', pattern: /(template|asset|svg|image|metadata)/i },
  { label: 'ai_content', pattern: /\b(?:ai|llm|prompt|completion|generated)\b/i },
  { label: 'deeplink_custom_protocol', pattern: /(deeplink|protocol|url\.searchParams|location\.search|hashchange)/i }
];

const HTML_SINK_PATTERNS = [
  { label: 'dom_inner_html', pattern: /\.innerHTML\s*=/g },
  { label: 'dom_outer_html', pattern: /\.outerHTML\s*=/g },
  { label: 'dom_insert_adjacent_html', pattern: /\.insertAdjacentHTML\s*\(/g },
  { label: 'dom_parser_html', pattern: /DOMParser\s*\(|\.parseFromString\s*\(/g },
  { label: 'range_contextual_fragment', pattern: /\.createContextualFragment\s*\(/g },
  { label: 'iframe_srcdoc', pattern: /\.srcdoc\s*=/g },
  { label: 'dynamic_import', pattern: /import\s*\(\s*[^'"`]/g },
  { label: 'eval', pattern: /\beval\s*\(/g },
  { label: 'function_constructor', pattern: /\bnew\s+Function\s*\(/g },
  { label: 'string_timer', pattern: /\bset(?:Timeout|Interval)\s*\(\s*['"`]/g }
];

function stableHash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function normalizeCheckName(name) {
  return String(name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function idToPascalCase(id) {
  return String(id || '').toLowerCase().split('_').filter(Boolean).map(part => part.charAt(0).toUpperCase() + part.slice(1)).join('');
}

function checkIdForName(name) {
  const normalized = normalizeCheckName(name);
  for (const id of FINDING_IDS) {
    if (normalizeCheckName(id) === normalized)
      return id;
  }
  return null;
}

export function isStaticTrustAuditCheckName(name) {
  return checkIdForName(name) != null;
}

function lineColumnFromIndex(content, index) {
  const boundedIndex = Math.max(0, index || 0);
  const before = content.slice(0, boundedIndex);
  const lines = before.split('\n');
  return {
    line: lines.length,
    column: lines[lines.length - 1].length
  };
}

function sampleAt(content, line) {
  return content.split('\n')[Math.max(0, (line || 1) - 1)] || '';
}

function issueProperties(baseProperties) {
  return Object.assign({
    issueType: 'finding',
    issueClassification: 'finding'
  }, baseProperties);
}

function buildIssue(file, fileClassification, content, location, id, description, severityValue, confidenceValue, properties) {
  const matchedLineSample = sampleAt(content, location.line);
  const check = { id, constructor: { name: idToPascalCase(id) } };
  return {
    file,
    sample: matchedLineSample,
    location,
    id,
    description,
    properties,
    severity: severityValue,
    confidence: confidenceValue,
    manualReview: true,
    shortenedURL: 'https://github.com/doyensec/electronegativity/wiki',
    visibility: isDisabledByInlineComment(sampleAt(content, 1), matchedLineSample, check, sourceTypes.JAVASCRIPT),
    constructorName: id,
    fileClassification
  };
}

function createRecord(records, record) {
  records.push(record);
  return record;
}

function createRelationship(relationships, relationship) {
  relationships.push(relationship);
  return relationship;
}

function sourceFileKey(file) {
  return `source_file|${file}`;
}

function recordKey(entityType, file, line, column, label) {
  return `${entityType}|${file}|${line || 1}|${column || 0}|${label || 'dynamic'}`;
}

function addDeclaredIn(relationships, record, file) {
  createRelationship(relationships, {
    relationship_type: 'declared_in',
    from_key: record.key,
    to_key: sourceFileKey(file),
    file,
    line: record.line,
    column: record.column
  });
}

function uniqueSorted(values) {
  return Array.from(new Set(values.filter(value => value != null))).sort();
}

function snippetAround(content, index, radius = 500) {
  return content.slice(Math.max(0, index - radius), Math.min(content.length, index + radius));
}

function blockFrom(content, index, radius = 1200) {
  return snippetAround(content, index, radius);
}

function enclosingBraceBlock(content, index, radius = 500) {
  const openIndex = content.lastIndexOf('{', index);
  if (openIndex < 0)
    return snippetAround(content, index, radius);

  let depth = 0;
  for (let i = openIndex; i < content.length; i++) {
    const ch = content[i];
    if (ch === '{')
      depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0)
        return content.slice(openIndex, i + 1);
    }
  }

  return snippetAround(content, index, radius);
}

function hasUrlValidation(text) {
  return /\bnew\s+URL\s*\(|\bURL\s*\(|allowed[A-Za-z0-9_]*\s*\.\s*(?:includes|has)|allowlist|whitelist|\.(?:origin|hostname|protocol)\b|startsWith\s*\(|endsWith\s*\(/i.test(text);
}

function deniesByDefault(text) {
  return /action\s*:\s*['"]deny['"]|\.preventDefault\s*\(|callback\s*\(\s*false\s*\)|return\s+false\b/i.test(text);
}

function hasAllowAllWindowOpen(text) {
  return /action\s*:\s*['"]allow['"]/i.test(text);
}

function isConstantUrlArgument(argumentSource) {
  return /^\s*['"`](https?:|mailto:|tel:)/.test(argumentSource || '');
}

function argumentInsideCall(content, callStartIndex) {
  const openIndex = content.indexOf('(', callStartIndex);
  if (openIndex < 0)
    return '';

  let depth = 0;
  for (let i = openIndex; i < content.length; i++) {
    const ch = content[i];
    if (ch === '(')
      depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0)
        return content.slice(openIndex + 1, i);
    }
  }

  return content.slice(openIndex + 1, openIndex + 80);
}

function cspDirectives(policy) {
  const directives = {};
  String(policy || '').split(';').forEach(part => {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0)
      return;
    directives[tokens[0].toLowerCase()] = tokens.slice(1);
  });
  return directives;
}

function directiveValues(directives, name) {
  return directives[name] || directives['default-src'] || [];
}

function policyHasScriptWildcard(directives) {
  const values = directiveValues(directives, 'script-src');
  return values.includes('*') || values.some(value => /^https?:$/.test(value));
}

function policyHasWeakObjectSrc(directives) {
  const values = directives['object-src'];
  return !values || !(values.length === 1 && values[0] === "'none'");
}

function policyHasBroadDefault(directives) {
  return (directives['default-src'] || []).includes('*');
}

function policyIsWeakForRendererXss(directives) {
  return policyHasBroadDefault(directives) ||
    policyHasScriptWildcard(directives) ||
    directiveValues(directives, 'script-src').includes("'unsafe-inline'") ||
    directiveValues(directives, 'script-src').includes("'unsafe-eval'") ||
    policyHasWeakObjectSrc(directives);
}

function extractCspPoliciesFromHtml($) {
  const policies = [];
  $('meta[http-equiv]').each(function() {
    const element = $(this);
    if (String(element.attr('http-equiv') || '').toLowerCase() !== 'content-security-policy')
      return;
    const policy = element.attr('content');
    if (policy)
      policies.push(policy);
  });
  return policies;
}

function buildHtmlIssue(file, fileClassification, content, location, id, description, severityValue, confidenceValue, properties) {
  const issue = buildIssue(file, fileClassification, content, location, id, description, severityValue, confidenceValue, properties);
  const matchedLineSample = sampleAt(content, location.line);
  const check = { id, constructor: { name: idToPascalCase(id) } };
  issue.visibility = isDisabledByInlineComment(sampleAt(content, 1), matchedLineSample, check, sourceTypes.HTML);
  return issue;
}

function regexMatches(content, pattern) {
  const matches = [];
  let match;
  pattern.lastIndex = 0;
  while ((match = pattern.exec(content)) !== null) {
    matches.push(match);
    if (match.index === pattern.lastIndex)
      pattern.lastIndex++;
  }
  return matches;
}

function hasStrongSanitizerNear(content, index) {
  const nearby = snippetAround(content, index, 350);
  return /DOMPurify\.sanitize|sanitizeHtml\s*\(|xssFilters|trustedTypes\.createPolicy/i.test(nearby);
}

function hasWeakSanitizerConfigNear(content, index) {
  const nearby = snippetAround(content, index, 500);
  return /sanitize(?:Html)?\s*\([^)]*(?:ADD_ATTR|ADD_TAGS|allowedTags\s*:\s*false|allowedAttributes\s*:\s*false|RETURN_TRUSTED_TYPE\s*:\s*false)/i.test(nearby);
}

function sourceLabelsForContext(file, context) {
  const labels = [];
  const haystack = context;
  SOURCE_VECTOR_RULES.forEach(rule => {
    if (rule.pattern.test(haystack))
      labels.push(rule.label);
  });
  return Array.from(new Set(labels));
}

function issueClassificationForFileProtocol() {
  return {
    issueType: 'finding',
    issueClassification: 'inventory',
    electronComponent: 'protocol',
    trustBoundary: 'app_to_file_protocol',
    confidenceReasons: ['file protocol app content observed'],
    nextAgentHint: 'Review whether file protocol content is mixed with untrusted navigation or permissive protocol privileges.'
  };
}

function protocolPrivilegeSummary(text) {
  const flags = {};
  ['standard', 'secure', 'supportFetchAPI', 'corsEnabled', 'stream', 'bypassCSP', 'allowServiceWorkers'].forEach(flag => {
    const match = new RegExp(`${flag}\\s*:\\s*(true|false)`, 'i').exec(text);
    if (match)
      flags[flag] = match[1].toLowerCase() === 'true';
  });
  return flags;
}

function hasPathTraversalRisk(text) {
  return /(request|req|url|parsedUrl|pathname)\s*\./i.test(text) ||
    /(new\s+URL\s*\([^)]*(request|req|url)|\.pathname|\.searchParams)/i.test(text);
}

function hasPathNormalizationGuard(text) {
  return /path\.(?:normalize|resolve)\s*\(|\.startsWith\s*\(|allowed[A-Za-z0-9_]*\s*\.\s*(?:includes|has)|allowlist|whitelist/i.test(text);
}

function addIssueIfEnabled(issues, enabledFindingIds, issue) {
  if (enabledFindingIds.has(issue.id))
    issues.push(issue);
}

export class StaticTrustCollector {
  constructor(options = {}) {
    this.records = [];
    this.relationships = [];
    this.issues = [];
    this.hypotheses = [];
    this.remoteContentObserved = false;
    this.permissionHandlerObserved = false;
    this.enabledFindingIds = new Set(FINDING_IDS);

    if (options.customScan && options.customScan.length > 0) {
      this.enabledFindingIds = new Set();
      options.customScan.forEach(name => {
        const id = checkIdForName(name);
        if (id)
          this.enabledFindingIds.add(id);
      });
    }

    (options.excludeFromScan || []).forEach(name => {
      const id = checkIdForName(name);
      if (id)
        this.enabledFindingIds.delete(id);
    });
  }

  collect(file, type, data, content, fileClassification) {
    if (!content)
      return;

    if (type === sourceTypes.JAVASCRIPT)
      this.collectJavaScript(file, content, fileClassification);
    else if (type === sourceTypes.HTML)
      this.collectHtml(file, data, content, fileClassification);
  }

  collectJavaScript(file, content, fileClassification) {
    this.collectNavigationAndExternalOpen(file, content, fileClassification);
    this.collectProtocol(file, content, fileClassification);
    this.collectPermissionHandlers(file, content, fileClassification);
    this.collectCspFromJavaScript(file, content, fileClassification);
    this.collectRendererSinks(file, content, fileClassification, 'javascript');
  }

  collectHtml(file, $, content, fileClassification) {
    this.collectFileProtocolHtml(file, $, content, fileClassification);
    this.collectCspFromHtml(file, $, content, fileClassification);
    this.collectRendererSinks(file, content, fileClassification, 'html');
  }

  collectNavigationAndExternalOpen(file, content, fileClassification) {
    regexMatches(content, /\.setWindowOpenHandler\s*\(/g).forEach(match => {
      const location = lineColumnFromIndex(content, match.index);
      const handlerText = argumentInsideCall(content, match.index);
      const record = createRecord(this.records, {
        key: recordKey('navigation_handler', file, location.line, location.column, 'setWindowOpenHandler'),
        entity_type: 'navigation_handler',
        title: 'setWindowOpenHandler handler',
        file,
        line: location.line,
        column: location.column,
        event_name: 'setWindowOpenHandler',
        denies_by_default: deniesByDefault(handlerText),
        allow_all: hasAllowAllWindowOpen(handlerText) && !hasUrlValidation(handlerText),
        url_validation_evidence: hasUrlValidation(handlerText) ? ['url_or_origin_allowlist'] : [],
        external_open_in_handler: /openExternal\s*\(/.test(handlerText)
      });
      addDeclaredIn(this.relationships, record, file);

      if (record.allow_all) {
        addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
          file,
          fileClassification,
          content,
          location,
          'WINDOW_OPEN_ALLOW_ALL',
          'Window-open handler allows new windows without visible URL or origin validation',
          severity.HIGH,
          confidence.FIRM,
          issueProperties({
            electronComponent: 'window',
            trustBoundary: 'renderer_to_new_window',
            confidenceReasons: ['setWindowOpenHandler returns allow without visible allowlist'],
            nextAgentHint: 'Review whether attacker-controlled renderer content can trigger this window-open path.'
          })
        ));
      }
    });

    regexMatches(content, /\.on\s*\(\s*['"](will-navigate|new-window)['"]/g).forEach(match => {
      const eventName = match[1];
      const location = lineColumnFromIndex(content, match.index);
      const handlerText = argumentInsideCall(content, match.index);
      const allowAll = !deniesByDefault(handlerText) && !hasUrlValidation(handlerText);
      const record = createRecord(this.records, {
        key: recordKey('navigation_handler', file, location.line, location.column, eventName),
        entity_type: 'navigation_handler',
        title: `${eventName} handler`,
        file,
        line: location.line,
        column: location.column,
        event_name: eventName,
        denies_by_default: deniesByDefault(handlerText),
        allow_all: allowAll,
        url_validation_evidence: hasUrlValidation(handlerText) ? ['url_or_origin_allowlist'] : [],
        external_open_in_handler: /openExternal\s*\(/.test(handlerText)
      });
      addDeclaredIn(this.relationships, record, file);

      if (allowAll) {
        addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
          file,
          fileClassification,
          content,
          location,
          'NAVIGATION_ALLOW_ALL',
          'Navigation handler does not visibly deny or validate navigations',
          severity.MEDIUM,
          confidence.FIRM,
          issueProperties({
            electronComponent: 'window',
            trustBoundary: 'renderer_navigation',
            confidenceReasons: [`${eventName} handler lacks visible deny-by-default or URL allowlist logic`],
            nextAgentHint: 'Check whether untrusted content can navigate this renderer to attacker-controlled origins.'
          })
        ));
      }
    });

    regexMatches(content, /\b(?:shell\s*\.\s*)?openExternal\s*\(/g).forEach(match => {
      const location = lineColumnFromIndex(content, match.index);
      const arg = argumentInsideCall(content, match.index);
      const nearby = enclosingBraceBlock(content, match.index, 250);
      const validated = isConstantUrlArgument(arg) || hasUrlValidation(nearby);
      const inWindowHandler = /\.setWindowOpenHandler\s*\(|['"](new-window|will-navigate)['"]/.test(snippetAround(content, match.index, 600));
      const record = createRecord(this.records, {
        key: recordKey('external_open', file, location.line, location.column, 'openExternal'),
        entity_type: 'external_open',
        title: 'shell.openExternal call',
        file,
        line: location.line,
        column: location.column,
        argument_kind: isConstantUrlArgument(arg) ? 'constant_url' : 'dynamic_or_variable',
        visible_url_validation: validated,
        in_window_or_navigation_handler: inWindowHandler
      });
      addDeclaredIn(this.relationships, record, file);

      if (!validated) {
        addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
          file,
          fileClassification,
          content,
          location,
          'OPEN_EXTERNAL_UNVALIDATED_URL',
          'shell.openExternal is called with a non-constant URL without visible URL validation',
          severity.MEDIUM,
          confidence.FIRM,
          issueProperties({
            electronComponent: 'window',
            trustBoundary: 'app_to_external_browser',
            confidenceReasons: ['dynamic openExternal argument', 'no nearby URL allowlist evidence'],
            nextAgentHint: 'Trace whether renderer-controlled URL data can reach this external-open call.'
          })
        ));

        if (inWindowHandler) {
          addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
            file,
            fileClassification,
            content,
            location,
            'OPEN_EXTERNAL_IN_WINDOW_HANDLER_UNVALIDATED',
            'Window-open or navigation handler forwards an unvalidated URL to shell.openExternal',
            severity.HIGH,
            confidence.FIRM,
            issueProperties({
              electronComponent: 'window',
              trustBoundary: 'renderer_to_external_browser',
              confidenceReasons: ['openExternal appears inside navigation/window-open handler', 'no nearby URL allowlist evidence'],
              nextAgentHint: 'Review whether attacker-controlled window-open URLs can trigger this external-open path.'
            })
          ));
        }
      }
    });
  }

  collectProtocol(file, content, fileClassification) {
    regexMatches(content, /\b(loadFile|loadURL)\s*\(/g).forEach(match => {
      const method = match[1];
      const arg = argumentInsideCall(content, match.index);
      if (method !== 'loadFile' && !/^\s*['"`]file:\/\//.test(arg))
        return;

      const location = lineColumnFromIndex(content, match.index);
      const record = createRecord(this.records, {
        key: recordKey('file_protocol_usage', file, location.line, location.column, method),
        entity_type: 'file_protocol_usage',
        title: `${method} file protocol app content`,
        file,
        line: location.line,
        column: location.column,
        source_kind: 'javascript',
        method,
        argument_kind: /^\s*['"`]/.test(arg) ? 'static' : 'dynamic'
      });
      addDeclaredIn(this.relationships, record, file);
      addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
        file,
        fileClassification,
        content,
        location,
        'FILE_PROTOCOL_APP_CONTENT_INVENTORY',
        'Application loads renderer content from the file protocol',
        severity.INFORMATIONAL,
        confidence.FIRM,
        issueClassificationForFileProtocol()
      ));
    });

    regexMatches(content, /protocol\s*\.\s*registerSchemesAsPrivileged\s*\(/g).forEach(match => {
      const location = lineColumnFromIndex(content, match.index);
      const text = blockFrom(content, match.index);
      const flags = protocolPrivilegeSummary(text);
      const record = createRecord(this.records, {
        key: recordKey('protocol_scheme', file, location.line, location.column, 'registerSchemesAsPrivileged'),
        entity_type: 'protocol_scheme',
        title: 'Custom protocol privilege registration',
        file,
        line: location.line,
        column: location.column,
        api: 'protocol.registerSchemesAsPrivileged',
        privileges: flags
      });
      addDeclaredIn(this.relationships, record, file);

      if (flags.bypassCSP) {
        addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
          file,
          fileClassification,
          content,
          location,
          'CUSTOM_PROTOCOL_BYPASS_CSP',
          'Custom protocol is registered with bypassCSP enabled',
          severity.HIGH,
          confidence.CERTAIN,
          issueProperties({
            electronComponent: 'protocol',
            trustBoundary: 'custom_protocol_to_renderer',
            confidenceReasons: ['protocol privilege bypassCSP is true'],
            nextAgentHint: 'Review custom protocol content sources because renderer CSP may not constrain script execution.'
          })
        ));
      }

      if ((flags.allowServiceWorkers || flags.supportFetchAPI || flags.corsEnabled) && flags.secure !== true) {
        addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
          file,
          fileClassification,
          content,
          location,
          'CUSTOM_PROTOCOL_RISKY_PRIVILEGE_COMBINATION',
          'Custom protocol combines powerful privileges without a visible secure protocol flag',
          severity.MEDIUM,
          confidence.FIRM,
          issueProperties({
            electronComponent: 'protocol',
            trustBoundary: 'custom_protocol_to_renderer',
            confidenceReasons: ['custom protocol uses fetch/CORS/service-worker related privileges', 'secure flag is not visibly true'],
            nextAgentHint: 'Review whether this scheme hosts attacker-influenced content or mixed trust data.'
          })
        ));
      }
    });

    regexMatches(content, /protocol\s*\.\s*(handle|registerFileProtocol|registerBufferProtocol|registerStringProtocol|registerStreamProtocol)\s*\(/g).forEach(match => {
      const api = match[1];
      const location = lineColumnFromIndex(content, match.index);
      const text = blockFrom(content, match.index);
      const pathInfluenced = hasPathTraversalRisk(text);
      const guarded = hasPathNormalizationGuard(text);
      const record = createRecord(this.records, {
        key: recordKey('protocol_handler', file, location.line, location.column, api),
        entity_type: 'protocol_handler',
        title: `Custom protocol handler: ${api}`,
        file,
        line: location.line,
        column: location.column,
        api: `protocol.${api}`,
        path_influenced_by_url: pathInfluenced,
        visible_path_normalization_or_allowlist: guarded
      });
      addDeclaredIn(this.relationships, record, file);

      if (pathInfluenced && !guarded) {
        addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
          file,
          fileClassification,
          content,
          location,
          'CUSTOM_PROTOCOL_FILE_PATH_TRAVERSAL_RISK',
          'Custom protocol handler appears to map URL-controlled path data to local files without visible normalization or allowlist',
          severity.HIGH,
          confidence.FIRM,
          issueProperties({
            electronComponent: 'protocol',
            trustBoundary: 'custom_protocol_to_file_system',
            confidenceReasons: ['handler reads URL path data', 'no nearby path normalization or allowlist evidence'],
            nextAgentHint: 'Review whether crafted custom protocol URLs can read unintended local files.'
          })
        ));
      }
    });
  }

  collectFileProtocolHtml(file, $, content, fileClassification) {
    const self = this;
    $('[src], [href]').each(function() {
      const element = $(this);
      const target = element.attr('src') || element.attr('href');
      if (!/^file:\/\//i.test(target || ''))
        return;
      const startIndex = this.startIndex || content.indexOf(target);
      const location = lineColumnFromIndex(content, startIndex);
      const record = createRecord(self.records, {
        key: recordKey('file_protocol_usage', file, location.line, location.column, target),
        entity_type: 'file_protocol_usage',
        title: 'HTML file protocol reference',
        file,
        line: location.line,
        column: location.column,
        source_kind: 'html',
        method: 'html_reference',
        target
      });
      addDeclaredIn(self.relationships, record, file);
      addIssueIfEnabled(self.issues, self.enabledFindingIds, buildHtmlIssue(
        file,
        fileClassification,
        content,
        location,
        'FILE_PROTOCOL_APP_CONTENT_INVENTORY',
        'Renderer markup references file protocol content',
        severity.INFORMATIONAL,
        confidence.FIRM,
        issueClassificationForFileProtocol()
      ));
    });
  }

  collectPermissionHandlers(file, content, fileClassification) {
    regexMatches(content, /setPermissionRequestHandler\s*\(/g).forEach(match => {
      this.permissionHandlerObserved = true;
      const location = lineColumnFromIndex(content, match.index);
      const text = argumentInsideCall(content, match.index);
      const allowAll = /callback\s*\(\s*true\s*\)/.test(text) && !/callback\s*\(\s*false\s*\)|return\s+false\b|allowed[A-Za-z0-9_]*\s*\.\s*(?:includes|has)/i.test(text);
      const originCheck = hasUrlValidation(text) || /requestingUrl|webContents\.getURL|senderFrame\.url/i.test(text);
      const permissionAllowlist = /(permission|perm)\s*[,=]|allowedPermissions|permissions\s*\.\s*(?:includes|has)|\[\s*['"][a-z-]+['"]/.test(text);
      const sensitivePermissions = SENSITIVE_PERMISSIONS.filter(permission => new RegExp(permission.replace('-', '[-_]'), 'i').test(text));
      const record = createRecord(this.records, {
        key: recordKey('permission_handler', file, location.line, location.column, 'setPermissionRequestHandler'),
        entity_type: 'permission_handler',
        title: 'Permission request handler',
        file,
        line: location.line,
        column: location.column,
        allow_all: allowAll,
        visible_origin_check: originCheck,
        visible_permission_allowlist: permissionAllowlist,
        sensitive_permissions: sensitivePermissions
      });
      addDeclaredIn(this.relationships, record, file);

      if (allowAll) {
        addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
          file,
          fileClassification,
          content,
          location,
          'PERMISSION_HANDLER_ALLOW_ALL',
          'Permission request handler grants permissions broadly',
          severity.HIGH,
          confidence.FIRM,
          issueProperties({
            electronComponent: 'permission',
            trustBoundary: 'renderer_to_electron_permission',
            confidenceReasons: ['callback(true) without visible deny-by-default or allowlist evidence'],
            nextAgentHint: 'Review which renderer origins can request sensitive Electron permissions.'
          })
        ));
      }

      if (!originCheck) {
        addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
          file,
          fileClassification,
          content,
          location,
          'PERMISSION_HANDLER_NO_ORIGIN_CHECK',
          'Permission request handler lacks visible requesting-origin validation',
          severity.MEDIUM,
          confidence.FIRM,
          issueProperties({
            electronComponent: 'permission',
            trustBoundary: 'renderer_to_electron_permission',
            confidenceReasons: ['setPermissionRequestHandler without visible URL/origin allowlist'],
            nextAgentHint: 'Review whether remote or untrusted renderer content can request permissions in this session.'
          })
        ));
      }
    });

    if (/loadURL\s*\(\s*['"`]https?:\/\//.test(content))
      this.remoteContentObserved = true;
  }

  collectCspFromJavaScript(file, content, fileClassification) {
    regexMatches(content, /Content-Security-Policy['"`]?\s*[:,]\s*['"`]([^'"`]+)['"`]/g).forEach(match => {
      this.recordCspPolicy(file, content, fileClassification, lineColumnFromIndex(content, match.index), match[1], 'javascript_header');
    });
  }

  collectCspFromHtml(file, $, content, fileClassification) {
    extractCspPoliciesFromHtml($).forEach(policy => {
      this.recordCspPolicy(file, content, fileClassification, lineColumnFromIndex(content, content.indexOf(policy)), policy, 'html_meta');
    });
  }

  recordCspPolicy(file, content, fileClassification, location, policy, sourceKind) {
    const directives = cspDirectives(policy);
    const scriptValues = directiveValues(directives, 'script-src');
    const unsafeInline = scriptValues.includes("'unsafe-inline'");
    const unsafeEval = scriptValues.includes("'unsafe-eval'");
    const scriptWildcard = policyHasScriptWildcard(directives);
    const weak = policyIsWeakForRendererXss(directives);
    const record = createRecord(this.records, {
      key: recordKey('csp_policy', file, location.line, location.column, sourceKind),
      entity_type: 'csp_policy',
      title: 'Content Security Policy',
      file,
      line: location.line,
      column: location.column,
      source_kind: sourceKind,
      policy,
      directives,
      meaningfully_reduces_renderer_js_risk: !weak
    });
    addDeclaredIn(this.relationships, record, file);

    if (unsafeInline)
      this.addCspIssue(file, fileClassification, content, location, 'CSP_UNSAFE_INLINE', 'Content Security Policy allows unsafe inline script execution', ['script-src unsafe-inline']);
    if (unsafeEval)
      this.addCspIssue(file, fileClassification, content, location, 'CSP_UNSAFE_EVAL', 'Content Security Policy allows unsafe eval script execution', ['script-src unsafe-eval']);
    if (scriptWildcard)
      this.addCspIssue(file, fileClassification, content, location, 'CSP_SCRIPT_SRC_WILDCARD', 'Content Security Policy allows broad script sources', ['script-src wildcard or scheme-wide source']);
    if (weak)
      this.addCspIssue(file, fileClassification, content, location, 'CSP_WEAK_FOR_RENDERER_XSS', 'Content Security Policy is weak for renderer XSS risk reduction', ['CSP does not strongly constrain renderer script execution']);
  }

  addCspIssue(file, fileClassification, content, location, id, description, reasons) {
    addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
      file,
      fileClassification,
      content,
      location,
      id,
      description,
      severity.MEDIUM,
      confidence.FIRM,
      issueProperties({
        electronComponent: 'renderer',
        trustBoundary: 'renderer_script_execution',
        confidenceReasons: reasons,
        nextAgentHint: 'Use this CSP quality signal when ranking renderer XSS and preload bridge hypotheses.'
      })
    ));
  }

  collectRendererSinks(file, content, fileClassification, sourceKind) {
    HTML_SINK_PATTERNS.forEach(sinkRule => {
      regexMatches(content, sinkRule.pattern).forEach(match => {
        const location = lineColumnFromIndex(content, match.index);
        const nearby = snippetAround(content, match.index, 600);
        const sourceLabels = sourceLabelsForContext(file, nearby);
        const strongExecutionSink = sinkRule.label === 'eval' || sinkRule.label === 'function_constructor';
        const hasUntrustedSignal = sourceLabels.length > 0;
        const sanitizerPresent = hasStrongSanitizerNear(content, match.index);
        const weakSanitizer = hasWeakSanitizerConfigNear(content, match.index) || !sanitizerPresent;
        const record = createRecord(this.records, {
          key: recordKey('renderer_sink', file, location.line, location.column, sinkRule.label),
          entity_type: 'renderer_sink',
          title: `Renderer sink: ${sinkRule.label}`,
          file,
          line: location.line,
          column: location.column,
          source_kind: sourceKind,
          sink_label: sinkRule.label,
          source_labels: sourceLabels,
          sanitizer_evidence: sanitizerPresent ? ['nearby sanitizer call'] : [],
          sanitizer_status: sanitizerPresent ? 'visible' : 'unknown'
        });
        addDeclaredIn(this.relationships, record, file);

        sourceLabels.forEach(sourceLabel => {
          const vectorRecord = createRecord(this.records, {
            key: recordKey('content_vector', file, location.line, location.column, `${sourceLabel}|${sinkRule.label}`),
            entity_type: 'content_vector',
            title: `Content vector: ${sourceLabel}`,
            file,
            line: location.line,
            column: location.column,
            source_label: sourceLabel,
            sink_label: sinkRule.label
          });
          addDeclaredIn(this.relationships, vectorRecord, file);
          createRelationship(this.relationships, {
            relationship_type: 'feeds_candidate_sink',
            from_key: vectorRecord.key,
            to_key: record.key,
            file,
            line: location.line,
            column: location.column
          });
        });

        if (hasUntrustedSignal || strongExecutionSink) {
          addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
            file,
            fileClassification,
            content,
            location,
            'RENDERER_POTENTIAL_XSS_SINK',
            'Renderer contains a JavaScript or HTML execution sink near untrusted-content indicators',
            severity.MEDIUM,
            confidence.TENTATIVE,
            issueProperties({
              electronComponent: 'renderer',
              trustBoundary: 'content_to_renderer_script',
              confidenceReasons: [`renderer sink: ${sinkRule.label}`].concat(sourceLabels.map(label => `source label: ${label}`)),
              nextAgentHint: 'Run focused renderer tracing to determine whether attacker-controlled content reaches this sink.'
            })
          ));
        }

        if (weakSanitizer && hasUntrustedSignal) {
          addIssueIfEnabled(this.issues, this.enabledFindingIds, buildIssue(
            file,
            fileClassification,
            content,
            location,
            'RENDERER_SANITIZER_WEAK_OR_UNKNOWN',
            'Renderer sink has nearby untrusted-content indicators without strong sanitizer evidence',
            severity.LOW,
            confidence.TENTATIVE,
            issueProperties({
              electronComponent: 'renderer',
              trustBoundary: 'content_to_renderer_script',
              confidenceReasons: sanitizerPresent ? ['sanitizer configuration may need review'] : ['no nearby sanitizer evidence'],
              nextAgentHint: 'Review sanitizer configuration and source-to-sink reachability before triage.'
            })
          ));
        }

        if (hasUntrustedSignal)
          this.addRendererHypothesis(file, location, sourceLabels[0], sinkRule.label, sanitizerPresent);
      });
    });
  }

  addRendererHypothesis(file, location, sourceLabel, sinkLabel, sanitizerPresent) {
    const candidateChain = [
      { kind: 'source', label: sourceLabel, file, line: location.line },
      { kind: 'sink', label: sinkLabel, file, line: location.line }
    ];
    const confidenceReasons = ['nearby source/sink labels', `renderer sink: ${sinkLabel}`];
    const negativeEvidence = ['no proven source-to-sink trace', 'runtime frame privilege unknown'];
    if (sanitizerPresent)
      negativeEvidence.push('nearby sanitizer evidence present');
    else
      confidenceReasons.push('no nearby sanitizer evidence');

    this.hypotheses.push({
      type: 'hypothesis',
      classification: 'hypothesis',
      title: `${sourceLabel} may reach ${sinkLabel}`,
      source_label: sourceLabel,
      sink_label: sinkLabel,
      electron_component: 'renderer',
      affected_window_or_channel: 'unknown_renderer',
      trust_boundary: 'content_to_renderer_script',
      bridge_label: 'context_bridge_or_hostrpc_unknown',
      impact_label: 'ipc_reachability_unknown',
      candidate_chain: candidateChain,
      confidence: sanitizerPresent ? 'low' : 'medium',
      confidence_reasons: confidenceReasons,
      negative_evidence: negativeEvidence,
      rank: sanitizerPresent ? 0.35 : 0.55,
      validation_state: 'static_only',
      missing_evidence: ['source-to-sink trace', 'runtime frame privilege', 'preload/bridge reachability'],
      next_agent_hint: 'Run renderer sink tracing for this file and then correlate with preload bridge inventory.'
    });
  }

  buildAuditResults() {
    if (this.remoteContentObserved && !this.permissionHandlerObserved) {
      const file = 'N/A';
      const location = { line: 0, column: 0 };
      addIssueIfEnabled(this.issues, this.enabledFindingIds, {
        file,
        sample: '',
        location,
        id: 'PERMISSION_HANDLER_MISSING_FOR_REMOTE_CONTENT',
        description: 'Remote renderer content was observed without a visible permission request handler',
        properties: issueProperties({
          electronComponent: 'permission',
          trustBoundary: 'remote_renderer_to_electron_permission',
          confidenceReasons: ['loadURL remote content observed', 'no setPermissionRequestHandler observed in scanned files'],
          nextAgentHint: 'Confirm whether the app intentionally relies on Electron defaults or registers permission handlers outside scanned files.'
        }),
        severity: severity.MEDIUM,
        confidence: confidence.TENTATIVE,
        manualReview: true,
        shortenedURL: 'https://github.com/doyensec/electronegativity/wiki',
        visibility: { excludesGlobal: [], inlineDisabled: false, globalCheckDisabled: false },
        constructorName: 'PERMISSION_HANDLER_MISSING_FOR_REMOTE_CONTENT',
        fileClassification: { parser_status: 'unknown' }
      });
    }

    return {
      issues: this.issues,
      hypotheses: this.hypotheses,
      componentInventory: {
        records: this.records,
        relationships: this.relationships
      }
    };
  }
}
