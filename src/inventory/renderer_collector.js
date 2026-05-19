import { parseWebPreferencesFeaturesString } from '../util/map';
import { sourceTypes } from '../parser/types';

const CONTAINER_TYPES = new Set(['BrowserWindow', 'BrowserView', 'WebContentsView']);
const WEBVIEW_INSECURE_PREFERENCES = {
  nodeIntegration: true,
  nodeIntegrationInSubFrames: true,
  webSecurity: false,
  sandbox: false,
  contextIsolation: false,
  allowRunningInsecureContent: true,
  experimentalFeatures: true,
  webviewTag: true
};

function propertyName(node) {
  if (!node)
    return null;

  if (typeof node.name === 'string')
    return node.name;

  if (typeof node.value === 'string' || typeof node.value === 'number')
    return String(node.value);

  return null;
}

function resolveIdentifier(node, scope, aliases = null) {
  if (!node || node.type !== 'Identifier')
    return node;

  if (aliases && aliases.has(node.name))
    return aliases.get(node.name);

  if (!scope || typeof scope.getVarInScope !== 'function')
    return node;

  const variable = scope.getVarInScope(node.name);
  if (!variable || !variable.defs || variable.defs.length === 0)
    return node;

  const definitionNode = variable.defs[0].node;
  if (!definitionNode)
    return node;

  if (definitionNode.type === 'VariableDeclarator' && definitionNode.init)
    return definitionNode.init;

  if (/FunctionExpression|ArrowFunctionExpression|FunctionDeclaration/.test(definitionNode.type))
    return definitionNode;

  return node;
}

function literalValue(node, scope, depth = 0, aliases = null) {
  if (!node || depth > 4)
    return undefined;

  const resolvedNode = resolveIdentifier(node, scope, aliases);
  if (resolvedNode !== node)
    return literalValue(resolvedNode, scope, depth + 1, aliases);

  switch (node.type) {
    case 'Literal':
      return node.value;
    case 'StringLiteral':
    case 'BooleanLiteral':
    case 'NumericLiteral':
      return node.value;
    case 'NullLiteral':
      return null;
    case 'TemplateLiteral':
      return node.expressions.length === 0 ? node.quasis.map(quasi => quasi.value.cooked).join('') : undefined;
    case 'UnaryExpression':
      if (node.operator === '!' && typeof literalValue(node.argument, scope, depth + 1, aliases) !== 'undefined')
        return !literalValue(node.argument, scope, depth + 1, aliases);
      if (node.operator === '-' && typeof literalValue(node.argument, scope, depth + 1, aliases) === 'number')
        return -literalValue(node.argument, scope, depth + 1, aliases);
      if (node.operator === '+' && typeof literalValue(node.argument, scope, depth + 1, aliases) === 'number')
        return +literalValue(node.argument, scope, depth + 1, aliases);
      return undefined;
    case 'ArrayExpression': {
      const values = [];
      for (const element of node.elements || []) {
        const value = literalValue(element, scope, depth + 1, aliases);
        if (typeof value === 'undefined')
          return undefined;
        values.push(value);
      }
      return values;
    }
    case 'ObjectExpression': {
      const result = {};
      for (const property of node.properties || []) {
        if (!property || (property.type !== 'Property' && property.type !== 'ObjectProperty'))
          return undefined;

        const key = propertyName(property.key);
        const value = literalValue(property.value, scope, depth + 1, aliases);
        if (!key || typeof value === 'undefined')
          return undefined;
        result[key] = value;
      }
      return result;
    }
    default:
      return undefined;
  }
}

function collectObjectInfo(node, scope, aliases = null) {
  const resolvedNode = resolveIdentifier(node, scope, aliases);
  if (!resolvedNode || resolvedNode.type !== 'ObjectExpression')
    return null;

  const staticValues = {};
  const dynamicKeys = [];
  const propertyNodes = {};

  for (const property of resolvedNode.properties || []) {
    if (!property || (property.type !== 'Property' && property.type !== 'ObjectProperty'))
      continue;

    const key = propertyName(property.key);
    if (!key)
      continue;

    propertyNodes[key] = property;
    const value = literalValue(property.value, scope, 0, aliases);
    if (typeof value === 'undefined')
      dynamicKeys.push(key);
    else
      staticValues[key] = value;
  }

  return {
    node: resolvedNode,
    staticValues,
    dynamicKeys,
    propertyNodes
  };
}

function expressionLabel(node) {
  if (!node)
    return null;

  if (node.type === 'Identifier')
    return node.name;

  if (node.type === 'ThisExpression')
    return 'this';

  if (node.type === 'MemberExpression') {
    const objectLabel = expressionLabel(node.object);
    const propertyLabel = node.computed ? literalValue(node.property, null) : propertyName(node.property);
    if (!objectLabel || propertyLabel == null)
      return null;
    return node.computed ? `${objectLabel}[${JSON.stringify(propertyLabel)}]` : `${objectLabel}.${propertyLabel}`;
  }

  return null;
}

function assignedName(parentNode, currentNode) {
  if (!parentNode)
    return null;

  if (parentNode.type === 'VariableDeclarator' && parentNode.init === currentNode)
    return expressionLabel(parentNode.id);

  if (parentNode.type === 'AssignmentExpression' && parentNode.right === currentNode)
    return expressionLabel(parentNode.left);

  return null;
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

function sourceFileKey(file) {
  return `source_file|${file}`;
}

function containerKey(file, line, column, containerType, containerName) {
  return `renderer_container|${file}|${line}|${column}|${containerType}|${containerName || 'anonymous'}`;
}

function preferencesKey(containerInventoryKey) {
  return `web_preferences|${containerInventoryKey}`;
}

function preloadKey(containerInventoryKey, preloadPath) {
  return `preload_script|${containerInventoryKey}|${preloadPath}`;
}

function loadTargetKey(containerInventoryKey, method, line, column, target) {
  return `load_target|${containerInventoryKey}|${method}|${line}|${column}|${target || 'dynamic'}`;
}

function sessionKey(containerInventoryKey, source, value) {
  return `session|${containerInventoryKey}|${source}|${value || 'dynamic'}`;
}

function sessionAliasKey(file, line, column, value) {
  return `session|${file}|${line}|${column}|fromPartition|${value || 'dynamic'}`;
}

function navigationHandlerKey(containerInventoryKey, eventName, line, column) {
  return `navigation_handler|${containerInventoryKey}|${eventName}|${line}|${column}`;
}

function webviewAttachHandlerKey(containerInventoryKey, line, column) {
  return `webview_attach_handler|${containerInventoryKey}|${line}|${column}`;
}

function globalSandboxKey(file, line, column, source) {
  return `global_sandbox|${file}|${line}|${column}|${source}`;
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function findContainerFromMemberExpression(memberExpression, containerAliases, webContentsAliases) {
  if (!memberExpression || memberExpression.type !== 'MemberExpression')
    return null;

  const directLabel = expressionLabel(memberExpression);
  if (directLabel && webContentsAliases.has(directLabel))
    return webContentsAliases.get(directLabel);

  const objectLabel = expressionLabel(memberExpression.object);
  const property = memberExpression.computed ? literalValue(memberExpression.property, null) : propertyName(memberExpression.property);

  if (objectLabel && property === 'webContents' && containerAliases.has(objectLabel))
    return containerAliases.get(objectLabel);

  if (objectLabel && webContentsAliases.has(objectLabel))
    return webContentsAliases.get(objectLabel);

  return null;
}

function analyzeWillAttachHandler(handlerNode) {
  const analysis = {
    inline_handler: /FunctionExpression|ArrowFunctionExpression|FunctionDeclaration/.test(handlerNode ? handlerNode.type : ''),
    prevents_attach: false,
    strips_preload: false,
    inspects_params_src: false,
    insecure_web_preferences: [],
    static_review: handlerNode ? 'inline_handler' : 'handler_not_resolved'
  };

  if (!analysis.inline_handler)
    return analysis;

  const eventParamName = handlerNode.params && handlerNode.params[0] && handlerNode.params[0].type === 'Identifier'
    ? handlerNode.params[0].name
    : null;
  const webPreferencesParamName = handlerNode.params && handlerNode.params[1] && handlerNode.params[1].type === 'Identifier'
    ? handlerNode.params[1].name
    : null;
  const paramsParamName = handlerNode.params && handlerNode.params[2] && handlerNode.params[2].type === 'Identifier'
    ? handlerNode.params[2].name
    : null;
  const stack = [];

  const visit = currentNode => {
    if (!currentNode)
      return;

    if (currentNode.type === 'CallExpression' &&
        currentNode.callee &&
        currentNode.callee.type === 'MemberExpression' &&
        propertyName(currentNode.callee.property) === 'preventDefault' &&
        eventParamName &&
        expressionLabel(currentNode.callee.object) === eventParamName) {
      analysis.prevents_attach = true;
    }

    if (currentNode.type === 'UnaryExpression' &&
        currentNode.operator === 'delete' &&
        currentNode.argument &&
        currentNode.argument.type === 'MemberExpression' &&
        webPreferencesParamName &&
        expressionLabel(currentNode.argument.object) === webPreferencesParamName) {
      const deletedKey = propertyName(currentNode.argument.property);
      if (deletedKey === 'preload' || deletedKey === 'preloadURL')
        analysis.strips_preload = true;
    }

    if (currentNode.type === 'AssignmentExpression' &&
        currentNode.left &&
        currentNode.left.type === 'MemberExpression' &&
        webPreferencesParamName &&
        expressionLabel(currentNode.left.object) === webPreferencesParamName) {
      const preferenceName = propertyName(currentNode.left.property);
      const assignedValue = literalValue(currentNode.right, null);
      if (hasOwn(WEBVIEW_INSECURE_PREFERENCES, preferenceName) && assignedValue === WEBVIEW_INSECURE_PREFERENCES[preferenceName])
        analysis.insecure_web_preferences.push(preferenceName);
      if ((preferenceName === 'preload' || preferenceName === 'preloadURL') && assignedValue == null)
        analysis.strips_preload = true;
    }

    if (currentNode.type === 'MemberExpression' &&
        paramsParamName &&
        expressionLabel(currentNode.object) === paramsParamName &&
        propertyName(currentNode.property) === 'src') {
      analysis.inspects_params_src = true;
    }

    stack.push(currentNode);
    for (const key of Object.keys(currentNode)) {
      const value = currentNode[key];
      if (!value)
        continue;
      if (Array.isArray(value)) {
        value.forEach(child => {
          if (child && typeof child.type === 'string')
            visit(child);
        });
      } else if (value && typeof value.type === 'string') {
        visit(value);
      }
    }
    stack.pop();
  };

  visit(handlerNode.body || handlerNode);
  analysis.insecure_web_preferences = Array.from(new Set(analysis.insecure_web_preferences)).sort();
  return analysis;
}

function createRecord(records, record) {
  records.push(record);
  return record;
}

function createRelationship(relationships, relationship) {
  relationships.push(relationship);
  return relationship;
}

function buildWebPreferencesRecord(file, containerRecord, webPreferencesInfo) {
  return {
    key: preferencesKey(containerRecord.key),
    entity_type: 'web_preferences',
    title: `${containerRecord.container_type} webPreferences`,
    file,
    line: webPreferencesInfo.line,
    column: webPreferencesInfo.column,
    container_type: containerRecord.container_type,
    static_values: webPreferencesInfo.staticValues,
    dynamic_keys: webPreferencesInfo.dynamicKeys
  };
}

export class RendererInventoryCollector {
  constructor() {
    this.records = [];
    this.relationships = [];
  }

  collect(file, type, data, content) {
    if (!data)
      return;

    switch (type) {
      case sourceTypes.JAVASCRIPT:
        this.collectJavaScript(file, data);
        break;
      case sourceTypes.HTML:
        this.collectHtml(file, data, content);
        break;
      default:
        break;
    }
  }

  buildComponentInventory() {
    return {
      records: this.records.slice(),
      relationships: this.relationships.slice()
    };
  }

  collectJavaScript(file, rootData) {
    const stack = [];
    const containerAliases = new Map();
    const webContentsAliases = new Map();
    const sessionAliases = new Map();
    const localAliases = new Map();
    const fileContainerKeys = [];
    const fileSandboxRecordKeys = [];
    const astParser = rootData.astParser;
    const scope = rootData.Scope;

    astParser.traverseTree(rootData, {
      enter: nodeLike => {
        const astNode = astParser.getNode(nodeLike);
        const parentNode = stack.length > 0 ? stack[stack.length - 1] : null;
        if (scope && typeof scope.updateFunctionScope === 'function')
          scope.updateFunctionScope(astNode, 'enter');

        if (astNode.type === 'NewExpression' &&
            astNode.callee &&
            CONTAINER_TYPES.has(astNode.callee.name)) {
          const containerName = assignedName(parentNode, astNode);
          const record = createRecord(this.records, {
            key: containerKey(file, astNode.loc.start.line, astNode.loc.start.column, astNode.callee.name, containerName),
            entity_type: 'renderer_container',
            title: `${astNode.callee.name} renderer container`,
            file,
            line: astNode.loc.start.line,
            column: astNode.loc.start.column,
            source_kind: 'javascript',
            container_type: astNode.callee.name,
            container_name: containerName,
            creation: 'new_expression'
          });

          fileContainerKeys.push(record.key);
          createRelationship(this.relationships, {
            key: `declared_in|${record.key}|${sourceFileKey(file)}`,
            relationship_type: 'declared_in',
            from_key: record.key,
            to_key: sourceFileKey(file),
            file,
            line: astNode.loc.start.line,
            column: astNode.loc.start.column
          });

          if (containerName)
            containerAliases.set(containerName, record.key);

          const optionsArgument = astNode.arguments && astNode.arguments.length > 0 ? resolveIdentifier(astNode.arguments[0], scope, localAliases) : null;
          const optionsInfo = collectObjectInfo(optionsArgument, scope, localAliases);
          if (optionsInfo && hasOwn(optionsInfo.propertyNodes, 'webPreferences')) {
            const webPreferencesProperty = optionsInfo.propertyNodes.webPreferences;
            const webPreferencesNode = resolveIdentifier(webPreferencesProperty.value, scope, localAliases);
            const webPreferencesObjectInfo = collectObjectInfo(webPreferencesNode, scope, localAliases);
            const webPreferencesRecord = buildWebPreferencesRecord(file, record, {
              line: webPreferencesProperty.key.loc.start.line,
              column: webPreferencesProperty.key.loc.start.column,
              staticValues: webPreferencesObjectInfo ? webPreferencesObjectInfo.staticValues : {},
              dynamicKeys: webPreferencesObjectInfo ? webPreferencesObjectInfo.dynamicKeys : ['*dynamic*']
            });
            createRecord(this.records, webPreferencesRecord);
            createRelationship(this.relationships, {
              key: `has_web_preferences|${record.key}|${webPreferencesRecord.key}`,
              relationship_type: 'has_web_preferences',
              from_key: record.key,
              to_key: webPreferencesRecord.key,
              file,
              line: webPreferencesRecord.line,
              column: webPreferencesRecord.column
            });

            const staticWebPreferences = webPreferencesObjectInfo ? webPreferencesObjectInfo.staticValues : {};

            if (typeof staticWebPreferences.preload === 'string') {
              const preloadRecord = createRecord(this.records, {
                key: preloadKey(record.key, staticWebPreferences.preload),
                entity_type: 'preload_script',
                title: 'Preload script',
                file,
                line: webPreferencesProperty.key.loc.start.line,
                column: webPreferencesProperty.key.loc.start.column,
                preload_path: staticWebPreferences.preload
              });
              createRelationship(this.relationships, {
                key: `uses_preload|${record.key}|${preloadRecord.key}`,
                relationship_type: 'uses_preload',
                from_key: record.key,
                to_key: preloadRecord.key,
                file,
                line: preloadRecord.line,
                column: preloadRecord.column
              });
            }

            if (typeof staticWebPreferences.partition === 'string') {
              const sessionRecord = createRecord(this.records, {
                key: sessionKey(record.key, 'partition', staticWebPreferences.partition),
                entity_type: 'session',
                title: 'Renderer session partition',
                file,
                line: webPreferencesProperty.key.loc.start.line,
                column: webPreferencesProperty.key.loc.start.column,
                source: 'webPreferences.partition',
                partition: staticWebPreferences.partition
              });
              createRelationship(this.relationships, {
                key: `uses_session|${record.key}|${sessionRecord.key}`,
                relationship_type: 'uses_session',
                from_key: record.key,
                to_key: sessionRecord.key,
                file,
                line: sessionRecord.line,
                column: sessionRecord.column
              });
            } else if (webPreferencesObjectInfo &&
                       hasOwn(webPreferencesObjectInfo.propertyNodes, 'session') &&
                       webPreferencesObjectInfo.propertyNodes.session.value.type === 'Identifier' &&
                       sessionAliases.has(webPreferencesObjectInfo.propertyNodes.session.value.name)) {
              createRelationship(this.relationships, {
                key: `uses_session|${record.key}|${sessionAliases.get(webPreferencesObjectInfo.propertyNodes.session.value.name)}`,
                relationship_type: 'uses_session',
                from_key: record.key,
                to_key: sessionAliases.get(webPreferencesObjectInfo.propertyNodes.session.value.name),
                file,
                line: webPreferencesProperty.key.loc.start.line,
                column: webPreferencesProperty.key.loc.start.column
              });
            }
          }
        }

        if (astNode.type === 'VariableDeclarator' && astNode.id && astNode.id.type === 'Identifier' && astNode.init) {
          const aliasName = astNode.id.name;

          if (astNode.init.type === 'ObjectExpression' || astNode.init.type === 'ArrayExpression' || astNode.init.type === 'Literal')
            localAliases.set(aliasName, astNode.init);

          if (astNode.init.type === 'MemberExpression') {
            const containerKeyForContents = findContainerFromMemberExpression(astNode.init, containerAliases, webContentsAliases);
            if (containerKeyForContents)
              webContentsAliases.set(aliasName, containerKeyForContents);
          }

          if (astNode.init.type === 'CallExpression' &&
              astNode.init.callee &&
              astNode.init.callee.type === 'MemberExpression' &&
              propertyName(astNode.init.callee.property) === 'fromPartition') {
            const partition = literalValue(astNode.init.arguments && astNode.init.arguments[0], scope, 0, localAliases);
            const sessionRecord = createRecord(this.records, {
              key: sessionAliasKey(file, astNode.loc.start.line, astNode.loc.start.column, partition),
              entity_type: 'session',
              title: 'Session created from partition',
              file,
              line: astNode.loc.start.line,
              column: astNode.loc.start.column,
              source: 'session.fromPartition',
              partition: typeof partition === 'string' ? partition : null
            });
            sessionAliases.set(aliasName, sessionRecord.key);
          }
        }

        if (astNode.type === 'AssignmentExpression' && astNode.left && astNode.right && astNode.left.type === 'Identifier') {
          const aliasName = astNode.left.name;
          if (astNode.right.type === 'MemberExpression') {
            const containerKeyForContents = findContainerFromMemberExpression(astNode.right, containerAliases, webContentsAliases);
            if (containerKeyForContents)
              webContentsAliases.set(aliasName, containerKeyForContents);
          }
        }

        if (astNode.type === 'CallExpression' &&
            astNode.callee &&
            astNode.callee.type === 'MemberExpression') {
          const property = propertyName(astNode.callee.property);

          if ((property === 'loadURL' || property === 'loadFile')) {
            const objectLabel = expressionLabel(astNode.callee.object);
            let ownerContainerKey = objectLabel && containerAliases.has(objectLabel) ? containerAliases.get(objectLabel) : null;
            if (!ownerContainerKey && objectLabel && webContentsAliases.has(objectLabel))
              ownerContainerKey = webContentsAliases.get(objectLabel);
            if (!ownerContainerKey && astNode.callee.object.type === 'MemberExpression')
              ownerContainerKey = findContainerFromMemberExpression(astNode.callee.object, containerAliases, webContentsAliases);

            if (ownerContainerKey) {
              const target = literalValue(astNode.arguments && astNode.arguments[0], scope, 0, localAliases);
              const loadRecord = createRecord(this.records, {
                key: loadTargetKey(ownerContainerKey, property, astNode.loc.start.line, astNode.loc.start.column, target),
                entity_type: 'load_target',
                title: `${property} target`,
                file,
                line: astNode.loc.start.line,
                column: astNode.loc.start.column,
                method: property,
                target: typeof target === 'string' ? target : null,
                static_target: typeof target === 'string'
              });
              createRelationship(this.relationships, {
                key: `loads_target|${ownerContainerKey}|${loadRecord.key}`,
                relationship_type: 'loads_target',
                from_key: ownerContainerKey,
                to_key: loadRecord.key,
                file,
                line: loadRecord.line,
                column: loadRecord.column
              });
            }
          }

          const eventName = property === 'on' && astNode.arguments && astNode.arguments[0]
            ? literalValue(astNode.arguments[0], scope, 0, localAliases)
            : null;
          const handlerEvents = new Set(['will-navigate', 'new-window', 'will-attach-webview']);
          if ((property === 'setWindowOpenHandler') || (property === 'on' && handlerEvents.has(eventName))) {
            const ownerContainerKey = astNode.callee.object.type === 'MemberExpression'
              ? findContainerFromMemberExpression(astNode.callee.object, containerAliases, webContentsAliases)
              : (webContentsAliases.get(expressionLabel(astNode.callee.object)) || null);

            if (ownerContainerKey) {
              if (property === 'setWindowOpenHandler' || eventName === 'will-navigate' || eventName === 'new-window') {
                const navigationEvent = property === 'setWindowOpenHandler' ? 'setWindowOpenHandler' : eventName;
                const navigationRecord = createRecord(this.records, {
                  key: navigationHandlerKey(ownerContainerKey, navigationEvent, astNode.loc.start.line, astNode.loc.start.column),
                  entity_type: 'navigation_handler',
                  title: `${navigationEvent} handler`,
                  file,
                  line: astNode.loc.start.line,
                  column: astNode.loc.start.column,
                  event_name: navigationEvent
                });
                createRelationship(this.relationships, {
                  key: `has_navigation_handler|${ownerContainerKey}|${navigationRecord.key}`,
                  relationship_type: 'has_navigation_handler',
                  from_key: ownerContainerKey,
                  to_key: navigationRecord.key,
                  file,
                  line: navigationRecord.line,
                  column: navigationRecord.column
                });
              }

              if (eventName === 'will-attach-webview') {
                const handlerNode = astNode.arguments && astNode.arguments[1] ? resolveIdentifier(astNode.arguments[1], scope, localAliases) : null;
                const attachAnalysis = analyzeWillAttachHandler(handlerNode);
                const handlerRecord = createRecord(this.records, Object.assign({
                  key: webviewAttachHandlerKey(ownerContainerKey, astNode.loc.start.line, astNode.loc.start.column),
                  entity_type: 'webview_attach_handler',
                  title: 'will-attach-webview handler',
                  file,
                  line: astNode.loc.start.line,
                  column: astNode.loc.start.column,
                  event_name: 'will-attach-webview'
                }, attachAnalysis));
                createRelationship(this.relationships, {
                  key: `has_webview_attach_handler|${ownerContainerKey}|${handlerRecord.key}`,
                  relationship_type: 'has_webview_attach_handler',
                  from_key: ownerContainerKey,
                  to_key: handlerRecord.key,
                  file,
                  line: handlerRecord.line,
                  column: handlerRecord.column
                });
              }
            }
          }

          if (property === 'enableSandbox' && expressionLabel(astNode.callee.object) === 'app') {
            const sandboxRecord = createRecord(this.records, {
              key: globalSandboxKey(file, astNode.loc.start.line, astNode.loc.start.column, 'app.enableSandbox'),
              entity_type: 'global_sandbox',
              title: 'Global sandbox enabled',
              file,
              line: astNode.loc.start.line,
              column: astNode.loc.start.column,
              enabled: true,
              source: 'app.enableSandbox'
            });
            fileSandboxRecordKeys.push(sandboxRecord.key);
          }

          if (property === 'appendSwitch' &&
              expressionLabel(astNode.callee.object) === 'app.commandLine' &&
              literalValue(astNode.arguments && astNode.arguments[0], scope, 0, localAliases) === 'enable-sandbox') {
            const sandboxRecord = createRecord(this.records, {
              key: globalSandboxKey(file, astNode.loc.start.line, astNode.loc.start.column, 'app.commandLine.appendSwitch'),
              entity_type: 'global_sandbox',
              title: 'Global sandbox enabled',
              file,
              line: astNode.loc.start.line,
              column: astNode.loc.start.column,
              enabled: true,
              source: 'app.commandLine.appendSwitch'
            });
            fileSandboxRecordKeys.push(sandboxRecord.key);
          }
        }

        stack.push(astNode);
      },
      leave: nodeLike => {
        const astNode = astParser.getNode(nodeLike);
        stack.pop();
        if (scope && typeof scope.updateFunctionScope === 'function')
          scope.updateFunctionScope(astNode, 'leave');
      }
    });

    for (const containerInventoryKey of fileContainerKeys) {
      for (const sandboxRecordKey of fileSandboxRecordKeys) {
        createRelationship(this.relationships, {
          key: `global_sandbox_state|${containerInventoryKey}|${sandboxRecordKey}`,
          relationship_type: 'global_sandbox_state',
          from_key: containerInventoryKey,
          to_key: sandboxRecordKey,
          file
        });
      }
    }
  }

  collectHtml(file, cheerioObj, content) {
    const webviews = cheerioObj('webview');
    const self = this;

    webviews.each(function(index) {
      const element = cheerioObj(this);
      const startIndex = this.startIndex || 0;
      const location = lineColumnFromIndex(content, startIndex);
      const staticAttributes = {};
      const booleanAttributes = ['allowpopups', 'disablewebsecurity', 'nodeintegration', 'nodeintegrationinsubframes'];

      Object.keys(this.attribs || {}).sort().forEach(attributeName => {
        staticAttributes[attributeName] = element.attr(attributeName);
      });
      booleanAttributes.forEach(attributeName => {
        if (hasOwn(this.attribs || {}, attributeName))
          staticAttributes[attributeName] = true;
      });

      const webviewRecord = createRecord(self.records, {
        key: containerKey(file, location.line, location.column, 'webview', `webview_${index}`),
        entity_type: 'renderer_container',
        title: '<webview> renderer container',
        file,
        line: location.line,
        column: location.column,
        source_kind: 'html',
        container_type: 'webview',
        container_name: `webview_${index}`,
        static_attributes: staticAttributes
      });

      createRelationship(self.relationships, {
        key: `declared_in|${webviewRecord.key}|${sourceFileKey(file)}`,
        relationship_type: 'declared_in',
        from_key: webviewRecord.key,
        to_key: sourceFileKey(file),
        file,
        line: location.line,
        column: location.column
      });

      const parsedWebPreferences = parseWebPreferencesFeaturesString(element.attr('webpreferences') || '');
      const webPreferencesValues = Object.assign({}, parsedWebPreferences);

      if (hasOwn(this.attribs || {}, 'preload'))
        webPreferencesValues.preload = element.attr('preload');
      if (hasOwn(this.attribs || {}, 'partition'))
        webPreferencesValues.partition = element.attr('partition');
      if (hasOwn(this.attribs || {}, 'nodeintegration'))
        webPreferencesValues.nodeIntegration = true;
      if (hasOwn(this.attribs || {}, 'nodeintegrationinsubframes'))
        webPreferencesValues.nodeIntegrationInSubFrames = true;
      if (hasOwn(this.attribs || {}, 'disablewebsecurity'))
        webPreferencesValues.webSecurity = false;
      if (hasOwn(this.attribs || {}, 'allowpopups'))
        webPreferencesValues.allowpopups = true;

      if (Object.keys(webPreferencesValues).length > 0) {
        const webPreferencesRecord = createRecord(self.records, {
          key: preferencesKey(webviewRecord.key),
          entity_type: 'web_preferences',
          title: '<webview> webPreferences',
          file,
          line: location.line,
          column: location.column,
          container_type: 'webview',
          static_values: webPreferencesValues,
          dynamic_keys: []
        });
        createRelationship(self.relationships, {
          key: `has_web_preferences|${webviewRecord.key}|${webPreferencesRecord.key}`,
          relationship_type: 'has_web_preferences',
          from_key: webviewRecord.key,
          to_key: webPreferencesRecord.key,
          file,
          line: location.line,
          column: location.column
        });
      }

      const source = element.attr('src');
      if (typeof source === 'string' && source.length > 0) {
        const loadRecord = createRecord(self.records, {
          key: loadTargetKey(webviewRecord.key, 'src', location.line, location.column, source),
          entity_type: 'load_target',
          title: 'webview src target',
          file,
          line: location.line,
          column: location.column,
          method: 'src',
          target: source,
          static_target: true
        });
        createRelationship(self.relationships, {
          key: `loads_target|${webviewRecord.key}|${loadRecord.key}`,
          relationship_type: 'loads_target',
          from_key: webviewRecord.key,
          to_key: loadRecord.key,
          file,
          line: location.line,
          column: location.column
        });
      }

      const preload = element.attr('preload');
      if (typeof preload === 'string' && preload.length > 0) {
        const preloadRecord = createRecord(self.records, {
          key: preloadKey(webviewRecord.key, preload),
          entity_type: 'preload_script',
          title: 'Preload script',
          file,
          line: location.line,
          column: location.column,
          preload_path: preload
        });
        createRelationship(self.relationships, {
          key: `uses_preload|${webviewRecord.key}|${preloadRecord.key}`,
          relationship_type: 'uses_preload',
          from_key: webviewRecord.key,
          to_key: preloadRecord.key,
          file,
          line: location.line,
          column: location.column
        });
      }

      const partition = webPreferencesValues.partition;
      if (typeof partition === 'string' && partition.length > 0) {
        const sessionRecord = createRecord(self.records, {
          key: sessionKey(webviewRecord.key, 'partition', partition),
          entity_type: 'session',
          title: 'Renderer session partition',
          file,
          line: location.line,
          column: location.column,
          source: 'partition',
          partition
        });
        createRelationship(self.relationships, {
          key: `uses_session|${webviewRecord.key}|${sessionRecord.key}`,
          relationship_type: 'uses_session',
          from_key: webviewRecord.key,
          to_key: sessionRecord.key,
          file,
          line: location.line,
          column: location.column
        });
      }
    });
  }
}
