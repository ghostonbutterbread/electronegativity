import { severity, confidence } from '../finder';
import { sourceTypes } from '../parser/types';
import { isDisabledByInlineComment } from '../util/exceptions';

const IPC_HANDLER_METHODS = new Set(['handle', 'handleOnce', 'on', 'once']);
const IPC_FORWARD_METHODS = new Set(['send', 'sendSync', 'invoke', 'postMessage']);
const DANGEROUS_FS_METHODS = new Set(['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'open', 'openSync']);
const DANGEROUS_SHELL_METHODS = new Set(['openExternal', 'openPath', 'showItemInFolder']);
const DANGEROUS_CHILD_PROCESS_METHODS = new Set(['exec', 'execFile', 'execFileSync', 'execSync', 'fork', 'spawn', 'spawnSync']);
const VALIDATION_CALL_METHODS = new Set(['has', 'includes', 'indexOf', 'startsWith', 'endsWith']);
const LOCAL_BINDING_SHADOW = Symbol('LOCAL_BINDING_SHADOW');
class PreloadRawIpcExposureCheck { constructor() { this.id = 'PRELOAD_RAW_IPC_EXPOSURE'; } }
class PreloadArbitraryChannelForwardCheck { constructor() { this.id = 'PRELOAD_ARBITRARY_CHANNEL_FORWARD'; } }
class PreloadNodePrimitiveExposureCheck { constructor() { this.id = 'PRELOAD_NODE_PRIMITIVE_EXPOSURE'; } }
class PreloadDangerousApiWrapperCheck { constructor() { this.id = 'PRELOAD_DANGEROUS_API_WRAPPER'; } }
class IpcSenderValidationMissingCheck { constructor() { this.id = 'IPC_SENDER_VALIDATION_MISSING'; } }
class IpcDangerousSinkNoSenderValidationCheck { constructor() { this.id = 'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION'; } }
class IpcArbitraryForwardingToDangerousChannelCheck { constructor() { this.id = 'IPC_ARBITRARY_FORWARDING_TO_DANGEROUS_CHANNEL'; } }

const FINDING_CHECKS = [
  new PreloadRawIpcExposureCheck(),
  new PreloadArbitraryChannelForwardCheck(),
  new PreloadNodePrimitiveExposureCheck(),
  new PreloadDangerousApiWrapperCheck(),
  new IpcSenderValidationMissingCheck(),
  new IpcDangerousSinkNoSenderValidationCheck(),
  new IpcArbitraryForwardingToDangerousChannelCheck()
];
const FINDING_CHECK_BY_ID = new Map(FINDING_CHECKS.map(check => [check.id, check]));
const FINDING_CHECK_IDS = new Set(FINDING_CHECKS.map(check => check.id));

function normalizeCheckName(name) {
  return String(name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function phase6CheckIdForName(name) {
  const normalized = normalizeCheckName(name);
  for (const check of FINDING_CHECKS) {
    if (normalizeCheckName(check.id) === normalized || normalizeCheckName(check.constructor.name) === normalized)
      return check.id;
  }
  return null;
}

export function isPreloadIpcAuditCheckName(name) {
  return phase6CheckIdForName(name) != null;
}

function propertyName(node) {
  if (!node)
    return null;

  if (typeof node.name === 'string')
    return node.name;

  if (typeof node.value === 'string' || typeof node.value === 'number')
    return String(node.value);

  return null;
}

function addUnique(list, value) {
  if (value == null)
    return;

  if (!list.includes(value))
    list.push(value);
}

function uniqueSorted(values) {
  return Array.from(new Set(values.filter(value => value != null))).sort();
}

function lineColumn(node) {
  return {
    line: node && node.loc && node.loc.start ? node.loc.start.line : 1,
    column: node && node.loc && node.loc.start ? node.loc.start.column : 0
  };
}

function sampleAt(content, line) {
  return content.split('\n')[Math.max(0, (line || 1) - 1)] || '';
}

function walk(node, visitor, parent = null, ancestors = []) {
  if (!node || typeof node.type !== 'string')
    return;

  if (visitor(node, parent, ancestors) === false)
    return;

  Object.keys(node).forEach(key => {
    const value = node[key];
    if (Array.isArray(value)) {
      value.forEach(child => {
        if (child && typeof child.type === 'string')
          walk(child, visitor, node, ancestors.concat(node));
      });
    } else if (value && typeof value.type === 'string') {
      walk(value, visitor, node, ancestors.concat(node));
    }
  });
}

function walkWithScope(node, scope, visitor, parent = null, ancestors = []) {
  if (!node || typeof node.type !== 'string')
    return;

  if (scope && typeof scope.updateFunctionScope === 'function')
    scope.updateFunctionScope(node, 'enter');

  const shouldContinue = visitor(node, parent, ancestors) !== false;

  if (shouldContinue) {
    Object.keys(node).forEach(key => {
      const value = node[key];
      if (Array.isArray(value)) {
        value.forEach(child => {
          if (child && typeof child.type === 'string')
            walkWithScope(child, scope, visitor, node, ancestors.concat(node));
        });
      } else if (value && typeof value.type === 'string') {
        walkWithScope(value, scope, visitor, node, ancestors.concat(node));
      }
    });
  }

  if (scope && typeof scope.updateFunctionScope === 'function')
    scope.updateFunctionScope(node, 'leave');
}

function expressionLabel(node) {
  if (!node)
    return null;

  if (node.type === 'Identifier')
    return node.name;

  if (node.type === 'ThisExpression')
    return 'this';

  if (node.type === 'Super')
    return 'super';

  if (node.type === 'Literal' || node.type === 'StringLiteral')
    return typeof node.value === 'string' ? node.value : null;

  if (node.type === 'MemberExpression') {
    const objectLabel = expressionLabel(node.object);
    const propertyLabel = node.computed ? literalValue(node.property, null) : propertyName(node.property);
    if (!objectLabel || propertyLabel == null)
      return null;
    return node.computed ? `${objectLabel}[${JSON.stringify(propertyLabel)}]` : `${objectLabel}.${propertyLabel}`;
  }

  return null;
}

function hasRequireShadow(localAliases) {
  if (!localAliases)
    return false;

  if (localAliases === true)
    return true;

  return typeof localAliases.has === 'function' && localAliases.has('require');
}

function isRequireCall(node, moduleName = null, localAliases = null) {
  if (!node || node.type !== 'CallExpression' || node.callee.type !== 'Identifier' || node.callee.name !== 'require')
    return false;

  if (hasRequireShadow(localAliases))
    return false;

  if (moduleName == null)
    return true;

  return literalValue(node.arguments[0], null) === moduleName;
}

function normalizeResolveArgs(depth, localAliases) {
  if (depth && typeof depth !== 'number')
    return { depth: 0, localAliases: depth };

  return { depth, localAliases };
}

function collectLocalAliases(functionNode) {
  const aliases = new Map();

  parameterNames(functionNode.params).forEach(name => {
    aliases.set(name, LOCAL_BINDING_SHADOW);
  });

  const bodyStatements = functionNode.body && functionNode.body.type === 'BlockStatement' ?
    functionNode.body.body || [] :
    [];

  bodyStatements.forEach(statement => {
    if (statement && statement.type === 'FunctionDeclaration' && statement.id && statement.id.name) {
      aliases.set(statement.id.name, statement);
      return;
    }

    if (!statement || statement.type !== 'VariableDeclaration')
      return;

    (statement.declarations || []).forEach(declarator => addDeclaratorAlias(aliases, declarator));
  });

  return aliases;
}

function statementListForContainer(node) {
  if (!node)
    return null;

  if ((node.type === 'Program' || node.type === 'BlockStatement') && Array.isArray(node.body))
    return node.body;

  if (node.type === 'SwitchCase' && Array.isArray(node.consequent))
    return node.consequent;

  return null;
}

function addDeclaratorAlias(aliases, declarator, primitiveAliases = null, fallbackAliases = null) {
  if (!declarator || !declarator.id)
    return;

  if (declarator.id.type === 'Identifier') {
    aliases.set(declarator.id.name, declarator.init || LOCAL_BINDING_SHADOW);
    return;
  }

  boundPatternNames(declarator.id).forEach(name => aliases.set(name, LOCAL_BINDING_SHADOW));
  addElectronShellObjectPatternAliases(aliases, declarator, hasRequireShadow(aliases));
  addDangerousBuiltinDestructureAliases(aliases, declarator, hasRequireShadow(aliases), primitiveAliases, fallbackAliases);
}

function addVariableDeclarationAliases(aliases, statement, primitiveAliases = null, fallbackAliases = null) {
  if (!statement || statement.type !== 'VariableDeclaration')
    return;

  (statement.declarations || []).forEach(declarator => addDeclaratorAlias(aliases, declarator, primitiveAliases, fallbackAliases));
}

function addHoistedFunctionAliases(aliases, container) {
  const statements = statementListForContainer(container);
  if (!statements)
    return;

  statements.forEach(statement => {
    if (statement && statement.type === 'FunctionDeclaration' && statement.id && statement.id.name)
      aliases.set(statement.id.name, statement);
  });
}

function childAfterContainerInPath(container, path) {
  const containerIndex = path.indexOf(container);
  if (containerIndex < 0 || containerIndex >= path.length - 1)
    return null;

  return path[containerIndex + 1];
}

function addPrecedingVariableAliases(aliases, container, path, primitiveAliases = null, fallbackAliases = null) {
  const statements = statementListForContainer(container);
  const child = childAfterContainerInPath(container, path);
  if (!statements || !child)
    return;

  const childIndex = statements.indexOf(child);
  if (childIndex < 0)
    return;

  for (let i = 0; i < childIndex; i++)
    addVariableDeclarationAliases(aliases, statements[i], primitiveAliases, fallbackAliases);
}

function collectScopedLocalAliases(functionNode, currentNode, ancestors, primitiveAliases = null, fallbackAliases = null) {
  const aliases = new Map();
  const path = (ancestors || []).concat(currentNode ? [currentNode] : []);
  const functionIndex = path.indexOf(functionNode);
  const scopedPath = functionIndex >= 0 ? path.slice(functionIndex) : path;

  scopedPath.forEach(node => {
    if (isFunctionNode(node)) {
      parameterNames(node.params).forEach(name => {
        aliases.set(name, LOCAL_BINDING_SHADOW);
      });
    }
  });

  scopedPath.forEach(node => addHoistedFunctionAliases(aliases, node));
  scopedPath.forEach(node => addPrecedingVariableAliases(aliases, node, scopedPath, primitiveAliases, fallbackAliases));

  return aliases;
}

function localAliasesAt(functionNode, currentNode, ancestors, moduleAliases = null, primitiveAliases = null) {
  return mergeAliasMaps(collectScopedLocalAliases(functionNode, currentNode, ancestors, primitiveAliases, moduleAliases), moduleAliases);
}

function hasTopLevelRequireBinding(program) {
  return (program.body || []).some(node => {
    if (node.type === 'ImportDeclaration') {
      return (node.specifiers || []).some(specifier => specifier.local && specifier.local.name === 'require');
    }

    if (node.type === 'FunctionDeclaration')
      return node.id && node.id.name === 'require';

    if (node.type !== 'VariableDeclaration')
      return false;

    return (node.declarations || []).some(declarator => declarator.id && declarator.id.type === 'Identifier' && declarator.id.name === 'require');
  });
}

function collectModuleAliases(program, primitiveAliases = null) {
  const aliases = new Map();
  const moduleRequireShadowed = hasTopLevelRequireBinding(program);

  (program.body || []).forEach(node => {
    if (node.type === 'ImportDeclaration') {
      const moduleName = node.source && node.source.value;
      (node.specifiers || []).forEach(specifier => {
        if (specifier.type !== 'ImportSpecifier')
          return;

        const importedName = propertyName(specifier.imported);
        const localName = specifier.local && specifier.local.name;
        const methodSet = dangerousMethodSetForModule(moduleName);
        if (localName && methodSet && methodSet.has(importedName))
          aliases.set(localName, builtinMemberExpression(moduleName, importedName));
      });
      return;
    }

    if (node.type === 'VariableDeclaration') {
      (node.declarations || []).forEach(declarator => {
        if (declarator &&
            declarator.id &&
            declarator.id.type === 'Identifier' &&
            declarator.init) {
          aliases.set(declarator.id.name, declarator.init);
          return;
        }

        addElectronShellObjectPatternAliases(aliases, declarator, moduleRequireShadowed || hasRequireShadow(aliases));
        addDangerousBuiltinDestructureAliases(aliases, declarator, moduleRequireShadowed || hasRequireShadow(aliases), primitiveAliases);
      });
      return;
    }

    if (node.type === 'FunctionDeclaration' && node.id && node.id.name)
      aliases.set(node.id.name, node);
  });

  return aliases;
}

function cloneAliasSets(aliases) {
  const cloned = {};
  Object.keys(aliases).forEach(key => {
    cloned[key] = new Set(aliases[key]);
  });
  return cloned;
}

function removeModuleAliasName(aliases, name) {
  if (!name)
    return;

  Object.keys(aliases).forEach(key => {
    aliases[key].delete(name);
  });
}

function boundPatternNames(pattern) {
  const names = [];

  if (!pattern)
    return names;

  if (pattern.type === 'Identifier') {
    names.push(pattern.name);
    return names;
  }

  if (pattern.type === 'ObjectPattern') {
    (pattern.properties || []).forEach(property => {
      if (!property)
        return;

      if (property.type === 'RestElement') {
        names.push(...boundPatternNames(property.argument));
        return;
      }

      if (isObjectProperty(property))
        names.push(...boundPatternNames(property.value));
    });
    return names;
  }

  if (pattern.type === 'ArrayPattern') {
    (pattern.elements || []).forEach(element => {
      names.push(...boundPatternNames(element));
    });
    return names;
  }

  if (pattern.type === 'AssignmentPattern')
    return boundPatternNames(pattern.left);

  if (pattern.type === 'RestElement')
    return boundPatternNames(pattern.argument);

  return names;
}

function dangerousMethodSetForModule(moduleName) {
  switch (moduleName) {
    case 'fs':
      return DANGEROUS_FS_METHODS;
    case 'shell':
      return DANGEROUS_SHELL_METHODS;
    case 'child_process':
      return DANGEROUS_CHILD_PROCESS_METHODS;
    default:
      return null;
  }
}

function builtinModuleExpression(moduleName) {
  return {
    type: 'BuiltinModule',
    moduleName
  };
}

function builtinMemberExpression(moduleName, methodName) {
  return {
    type: 'MemberExpression',
    object: builtinModuleExpression(moduleName),
    property: {
      type: 'Identifier',
      name: methodName
    },
    computed: false
  };
}

function addDangerousBuiltinObjectPatternAliases(aliasMap, pattern, moduleName) {
  const methodSet = dangerousMethodSetForModule(moduleName);
  if (!pattern || pattern.type !== 'ObjectPattern' || !methodSet)
    return;

  (pattern.properties || []).forEach(property => {
    if (!isObjectProperty(property))
      return;

    const importedName = propertyName(property.key);
    const aliasName = property.value && property.value.type === 'Identifier' ? property.value.name : null;
    if (aliasName && methodSet.has(importedName))
      aliasMap.set(aliasName, builtinMemberExpression(moduleName, importedName));
  });
}

function addElectronNamespaceObjectPatternAliases(aliases, aliasMap, declarator) {
  if (!declarator || !declarator.id || declarator.id.type !== 'ObjectPattern')
    return;

  const namespaceName = declarator.init && declarator.init.type === 'Identifier' ? declarator.init.name : null;
  if (!namespaceName || !aliases.electronNamespace.has(namespaceName))
    return;

  (declarator.id.properties || []).forEach(property => {
    if (!isObjectProperty(property))
      return;

    const importedName = propertyName(property.key);
    const aliasName = property.value && property.value.type === 'Identifier' ? property.value.name : null;
    const aliasSet = moduleAliasesForBuiltin(aliases, importedName);
    if (aliasSet && aliasName) {
      aliasSet.add(aliasName);
      aliasMap.delete(aliasName);
    }
  });
}

function addElectronShellObjectPatternAliases(aliasMap, declarator, requireShadowed) {
  if (!declarator || !declarator.id || declarator.id.type !== 'ObjectPattern')
    return;

  if (!isRequireCall(declarator.init, 'electron', requireShadowed))
    return;

  (declarator.id.properties || []).forEach(property => {
    if (!isObjectProperty(property))
      return;

    const importedName = propertyName(property.key);
    const aliasName = property.value && property.value.type === 'Identifier' ? property.value.name : null;
    if (importedName === 'shell' && aliasName)
      aliasMap.set(aliasName, builtinModuleExpression('shell'));
  });
}

function addDangerousBuiltinDestructureAliases(aliasMap, declarator, requireShadowed, primitiveAliases = null, fallbackAliases = null) {
  if (!declarator || !declarator.id || declarator.id.type !== 'ObjectPattern')
    return;

  let moduleName = null;
  if (isRequireCall(declarator.init, null, requireShadowed)) {
    moduleName = literalValue(declarator.init.arguments[0], null);
  } else if (primitiveAliases) {
    const localAliases = mergeAliasMaps(aliasMap, fallbackAliases);
    moduleName = primitiveLabel(declarator.init, primitiveAliases, null, localAliases);
  }

  addDangerousBuiltinObjectPatternAliases(aliasMap, declarator.id, moduleName);
}

function shadowBindingName(aliases, moduleAliases, name) {
  removeModuleAliasName(aliases, name);
  if (moduleAliases)
    moduleAliases.set(name, LOCAL_BINDING_SHADOW);
}

function addScopedDeclaratorAliases(aliases, moduleAliases, declarator) {
  if (!declarator || !declarator.id)
    return;

  boundPatternNames(declarator.id).forEach(name => shadowBindingName(aliases, moduleAliases, name));

  const requireShadowed = hasRequireShadow(moduleAliases);
  addElectronShellObjectPatternAliases(moduleAliases, declarator, requireShadowed);
  addDangerousBuiltinDestructureAliases(moduleAliases, declarator, requireShadowed, aliases);

  if (isRequireCall(declarator.init, 'electron', requireShadowed)) {
    if (declarator.id.type === 'Identifier') {
      aliases.electronNamespace.add(declarator.id.name);
      moduleAliases.set(declarator.id.name, declarator.init);
      return;
    }

    if (declarator.id.type === 'ObjectPattern') {
      (declarator.id.properties || []).forEach(property => {
        if (!isObjectProperty(property))
          return;

        const importedName = propertyName(property.key);
        const aliasName = property.value && property.value.type === 'Identifier' ? property.value.name : null;
        const aliasSet = moduleAliasesForBuiltin(aliases, importedName);
        if (aliasSet && aliasName) {
          aliasSet.add(aliasName);
          moduleAliases.delete(aliasName);
        }
      });
      return;
    }
  }

  addElectronNamespaceObjectPatternAliases(aliases, moduleAliases, declarator);

  if (declarator.id.type !== 'Identifier')
    return;

  if (declarator.init)
    moduleAliases.set(declarator.id.name, declarator.init);

  if (!isRequireCall(declarator.init, null, requireShadowed))
    return;

  const moduleName = literalValue(declarator.init.arguments[0], null);
  const aliasSet = moduleAliasesForBuiltin(aliases, moduleName);
  if (aliasSet)
    aliasSet.add(declarator.id.name);
}

function addScopedVariableDeclarationAliases(aliases, moduleAliases, statement) {
  if (!statement || statement.type !== 'VariableDeclaration')
    return;

  (statement.declarations || []).forEach(declarator => addScopedDeclaratorAliases(aliases, moduleAliases, declarator));
}

function addScopedHoistedFunctionShadows(aliases, moduleAliases, container) {
  const statements = statementListForContainer(container);
  if (!statements)
    return;

  statements.forEach(statement => {
    if (statement && statement.type === 'FunctionDeclaration' && statement.id && statement.id.name)
      shadowBindingName(aliases, moduleAliases, statement.id.name);
  });
}

function addScopedPrecedingVariableAliases(aliases, moduleAliases, container, path) {
  const statements = statementListForContainer(container);
  const child = childAfterContainerInPath(container, path);
  if (!statements || !child)
    return;

  const childIndex = statements.indexOf(child);
  if (childIndex < 0)
    return;

  for (let i = 0; i < childIndex; i++)
    addScopedVariableDeclarationAliases(aliases, moduleAliases, statements[i]);
}

function scopedAliasesAtCall(baseAliases, baseModuleAliases, currentNode, ancestors) {
  const aliases = cloneAliasSets(baseAliases);
  const moduleAliases = new Map(baseModuleAliases || []);
  const path = (ancestors || []).concat(currentNode ? [currentNode] : []);

  path.forEach(node => {
    if (isFunctionNode(node)) {
      parameterNames(node.params).forEach(name => {
        shadowBindingName(aliases, moduleAliases, name);
      });
    }
  });

  path.forEach(node => addScopedHoistedFunctionShadows(aliases, moduleAliases, node));
  path.forEach(node => {
    if (node.type !== 'Program')
      addScopedPrecedingVariableAliases(aliases, moduleAliases, node, path);
  });

  return { aliases, moduleAliases };
}

function mergeAliasMaps(primaryAliases, fallbackAliases) {
  if (!fallbackAliases || fallbackAliases.size === 0)
    return primaryAliases || null;

  const aliases = new Map(fallbackAliases);
  if (primaryAliases) {
    primaryAliases.forEach((value, key) => {
      if (value === LOCAL_BINDING_SHADOW)
        aliases.set(key, LOCAL_BINDING_SHADOW);
      else
        aliases.set(key, value);
    });
  }

  return aliases;
}

function resolveIdentifier(node, scope, depth = 0, localAliases = null) {
  const args = normalizeResolveArgs(depth, localAliases);
  depth = args.depth;
  localAliases = args.localAliases;

  if (!node || node.type !== 'Identifier' || depth > 6)
    return node;

  if (localAliases && localAliases.get(node.name) === LOCAL_BINDING_SHADOW)
    return node;

  if (localAliases && localAliases.has(node.name))
    return resolveIdentifier(localAliases.get(node.name), scope, depth + 1, localAliases);

  if (!scope || typeof scope.getVarInScope !== 'function')
    return node;

  const variable = scope.getVarInScope(node.name);
  if (!variable || !variable.defs || variable.defs.length === 0)
    return node;

  const definitionNode = variable.defs[0].node;
  if (!definitionNode)
    return node;

  if (definitionNode.type === 'VariableDeclarator' && definitionNode.init)
    return resolveIdentifier(definitionNode.init, scope, depth + 1, localAliases);

  if (/FunctionExpression|ArrowFunctionExpression|FunctionDeclaration/.test(definitionNode.type))
    return definitionNode;

  return node;
}

function literalValue(node, scope, depth = 0, localAliases = null) {
  const args = normalizeResolveArgs(depth, localAliases);
  depth = args.depth;
  localAliases = args.localAliases;

  if (!node || depth > 6)
    return undefined;

  const resolvedNode = resolveIdentifier(node, scope, depth + 1, localAliases);
  if (resolvedNode !== node)
    return literalValue(resolvedNode, scope, depth + 1, localAliases);

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
    case 'ArrayExpression': {
      const values = [];
      for (const element of node.elements || []) {
        const value = literalValue(element, scope, depth + 1, localAliases);
        if (typeof value === 'undefined')
          return undefined;
        values.push(value);
      }
      return values;
    }
    default:
      return undefined;
  }
}

function arrayLiteralValues(node, scope, localAliases = null) {
  const values = literalValue(node, scope, localAliases);
  if (!Array.isArray(values))
    return null;

  return values.every(value => typeof value === 'string') ? values : null;
}

function primitiveLabelForIdentifierName(name, aliases) {
  if (name === 'require' || aliases.require.has(name))
    return 'require';
  if (name === 'process' || aliases.process.has(name))
    return 'process';
  if (name === 'Buffer' || aliases.Buffer.has(name))
    return 'Buffer';
  if (aliases.fs.has(name))
    return 'fs';
  if (aliases.path.has(name))
    return 'path';
  if (aliases.shell.has(name))
    return 'shell';
  if (aliases.child_process.has(name))
    return 'child_process';
  if (aliases.ipcRenderer.has(name))
    return 'ipcRenderer';
  return null;
}

function primitiveLabelForRequireCall(node, localAliases = null) {
  if (!isRequireCall(node, null, localAliases))
    return null;

  const moduleName = literalValue(node.arguments[0], null);
  if (moduleName === 'fs' || moduleName === 'path' || moduleName === 'child_process')
    return moduleName;

  return 'require';
}

function primitiveLabel(node, aliases, scope, localAliases = null) {
  if (!node)
    return null;

  if (node.type === 'BuiltinModule')
    return dangerousMethodSetForModule(node.moduleName) ? node.moduleName : null;

  if (node.type === 'Identifier') {
    if (localAliases && localAliases.has(node.name)) {
      if (localAliases.get(node.name) === LOCAL_BINDING_SHADOW)
        return null;

      const resolvedLocal = resolveIdentifier(node, scope, localAliases);
      return resolvedLocal !== node ? primitiveLabel(resolvedLocal, aliases, scope, localAliases) : null;
    }

    return primitiveLabelForIdentifierName(node.name, aliases);
  }

  if (node.type === 'MemberExpression') {
    if (matchesElectronMember(node, aliases, 'ipcRenderer'))
      return 'ipcRenderer';
    if (matchesElectronMember(node, aliases, 'shell'))
      return 'shell';
  }

  const resolvedNode = resolveIdentifier(node, scope, localAliases);
  if (resolvedNode !== node)
    return primitiveLabel(resolvedNode, aliases, scope, localAliases);

  if (resolvedNode.type === 'Identifier')
    return primitiveLabelForIdentifierName(resolvedNode.name, aliases);

  const requirePrimitive = primitiveLabelForRequireCall(resolvedNode, localAliases);
  if (requirePrimitive)
    return requirePrimitive;

  if (resolvedNode.type === 'CallExpression' && matchesElectronMember(resolvedNode.callee, aliases, 'ipcRenderer'))
    return 'ipcRenderer';

  if (resolvedNode.type === 'MemberExpression') {
    const objectPrimitive = primitiveLabel(resolvedNode.object, aliases, scope, localAliases);
    if (objectPrimitive)
      return objectPrimitive;

    if (matchesElectronMember(resolvedNode, aliases, 'ipcRenderer'))
      return 'ipcRenderer';
    if (matchesElectronMember(resolvedNode, aliases, 'shell'))
      return 'shell';
  }

  return null;
}

function matchesElectronMember(node, aliases, memberName) {
  if (!node || node.type !== 'MemberExpression')
    return false;

  const property = node.computed ? literalValue(node.property, null) : propertyName(node.property);
  if (property !== memberName)
    return false;

  if (node.object.type === 'Identifier' && aliases.electronNamespace.has(node.object.name))
    return true;

  return false;
}

function moduleAliasesForBuiltin(aliases, moduleName) {
  switch (moduleName) {
    case 'contextBridge':
      return aliases.contextBridge;
    case 'ipcMain':
      return aliases.ipcMain;
    case 'ipcRenderer':
      return aliases.ipcRenderer;
    case 'shell':
      return aliases.shell;
    case 'fs':
      return aliases.fs;
    case 'path':
      return aliases.path;
    case 'child_process':
      return aliases.child_process;
    default:
      return null;
  }
}

function collectAliases(program) {
  const aliases = {
    electronNamespace: new Set(),
    contextBridge: new Set(),
    ipcMain: new Set(),
    ipcRenderer: new Set(),
    shell: new Set(),
    fs: new Set(),
    path: new Set(),
    child_process: new Set(),
    require: new Set(['require']),
    process: new Set(['process']),
    Buffer: new Set(['Buffer'])
  };
  const moduleRequireShadowed = hasTopLevelRequireBinding(program);

  (program.body || []).forEach(node => {
    if (node.type === 'ImportDeclaration') {
      const moduleName = node.source && node.source.value;
      (node.specifiers || []).forEach(specifier => {
        if (moduleName === 'electron') {
          if (specifier.type === 'ImportNamespaceSpecifier' || specifier.type === 'ImportDefaultSpecifier')
            aliases.electronNamespace.add(specifier.local.name);
          if (specifier.type === 'ImportSpecifier') {
            const importedName = propertyName(specifier.imported);
            const aliasSet = moduleAliasesForBuiltin(aliases, importedName);
            if (aliasSet)
              aliasSet.add(specifier.local.name);
          }
        } else {
          const aliasSet = moduleAliasesForBuiltin(aliases, moduleName);
          if (aliasSet)
            aliasSet.add(specifier.local.name);
        }
      });
      return;
    }

    if (node.type !== 'VariableDeclaration')
      return;

    (node.declarations || []).forEach(declarator => {
      if (!declarator || !declarator.id || !declarator.init)
        return;

      if (isRequireCall(declarator.init, 'electron', moduleRequireShadowed)) {
        if (declarator.id.type === 'Identifier') {
          aliases.electronNamespace.add(declarator.id.name);
          return;
        }

        if (declarator.id.type === 'ObjectPattern') {
          (declarator.id.properties || []).forEach(property => {
            if (!isObjectProperty(property))
              return;

            const importedName = propertyName(property.key);
            const aliasName = property.value && property.value.type === 'Identifier' ? property.value.name : null;
            const aliasSet = moduleAliasesForBuiltin(aliases, importedName);
            if (aliasSet && aliasName)
              aliasSet.add(aliasName);
          });
          return;
        }
      }

      const namespaceName = declarator.init && declarator.init.type === 'Identifier' ? declarator.init.name : null;
      if (declarator.id.type === 'ObjectPattern' && namespaceName && aliases.electronNamespace.has(namespaceName)) {
        (declarator.id.properties || []).forEach(property => {
          if (!isObjectProperty(property))
            return;

          const importedName = propertyName(property.key);
          const aliasName = property.value && property.value.type === 'Identifier' ? property.value.name : null;
          const aliasSet = moduleAliasesForBuiltin(aliases, importedName);
          if (aliasSet && aliasName)
            aliasSet.add(aliasName);
        });
        return;
      }

      if (declarator.id.type !== 'Identifier' || !isRequireCall(declarator.init, null, moduleRequireShadowed))
        return;

      const moduleName = literalValue(declarator.init.arguments[0], null);
      const aliasSet = moduleAliasesForBuiltin(aliases, moduleName);
      if (aliasSet)
        aliasSet.add(declarator.id.name);
    });
  });

  return aliases;
}

function isObjectProperty(property) {
  return property && (property.type === 'Property' || property.type === 'ObjectProperty');
}

function isObjectMethod(property) {
  return property && property.type === 'ObjectMethod';
}

function objectPropertyValue(property) {
  if (isObjectMethod(property))
    return property;

  if (isObjectProperty(property))
    return property.value;

  return null;
}

function isContextBridgeExposeCall(callee, aliases) {
  if (!callee || callee.type !== 'MemberExpression')
    return false;

  const property = callee.computed ? literalValue(callee.property, null) : propertyName(callee.property);
  if (property !== 'exposeInMainWorld')
    return false;

  if (callee.object.type === 'Identifier' && aliases.contextBridge.has(callee.object.name))
    return true;

  return matchesElectronMember(callee.object, aliases, 'contextBridge');
}

function ipcHandlerType(callee, aliases) {
  if (!callee || callee.type !== 'MemberExpression')
    return null;

  const property = callee.computed ? literalValue(callee.property, null) : propertyName(callee.property);
  if (!IPC_HANDLER_METHODS.has(property))
    return null;

  if (callee.object.type === 'Identifier' && aliases.ipcMain.has(callee.object.name))
    return property;

  if (matchesElectronMember(callee.object, aliases, 'ipcMain'))
    return property;

  return null;
}

function isFunctionNode(node) {
  return Boolean(node && /FunctionExpression|ArrowFunctionExpression|FunctionDeclaration|ObjectMethod/.test(node.type));
}

function parameterNames(params) {
  const names = [];
  (params || []).forEach(param => {
    if (!param)
      return;

    if (param.type === 'Identifier')
      names.push(param.name);
  });
  return names;
}

function referencesIdentifier(node, names, scope = null, depth = 0, localAliases = null) {
  const args = normalizeResolveArgs(depth, localAliases);
  depth = args.depth;
  localAliases = args.localAliases;

  if (!node || depth > 6)
    return false;

  const resolvedNode = resolveIdentifier(node, scope, localAliases);
  if (resolvedNode !== node)
    return referencesIdentifier(resolvedNode, names, scope, depth + 1, localAliases);

  let found = false;

  walk(node, currentNode => {
    if (currentNode.type === 'Identifier' && names.has(currentNode.name)) {
      found = true;
      return false;
    }
    return undefined;
  });

  return found;
}

function memberCallInfo(node, aliases, scope, localAliases = null) {
  if (!node || node.type !== 'CallExpression')
    return null;

  const resolvedCallee = resolveIdentifier(node.callee, scope, localAliases);
  if (!resolvedCallee || resolvedCallee.type !== 'MemberExpression')
    return null;

  const property = resolvedCallee.computed ? literalValue(resolvedCallee.property, scope, localAliases) : propertyName(resolvedCallee.property);
  const objectPrimitive = primitiveLabel(resolvedCallee.object, aliases, scope, localAliases);

  return {
    callee: resolvedCallee,
    property,
    objectPrimitive
  };
}

function isLiteralAllowlistReceiver(node, scope, localAliases = null) {
  if (!node)
    return false;

  if (node.type === 'ArrayExpression')
    return Array.isArray(arrayLiteralValues(node, scope, localAliases));

  if (node.type === 'Identifier') {
    const resolvedNode = resolveIdentifier(node, scope, localAliases);
    return resolvedNode !== node ? isLiteralAllowlistReceiver(resolvedNode, scope, localAliases) : false;
  }

  if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'Set')
    return Array.isArray(arrayLiteralValues(node.arguments[0], scope, localAliases));

  if (node.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'Set')
    return Array.isArray(arrayLiteralValues(node.arguments[0], scope, localAliases));

  return false;
}

function isControlExpressionWrapper(parent, child) {
  if (!parent)
    return false;

  if ((parent.type === 'UnaryExpression' || parent.type === 'UpdateExpression') && parent.argument === child)
    return true;

  if (parent.type === 'LogicalExpression' && (parent.left === child || parent.right === child))
    return true;

  if (parent.type === 'BinaryExpression' && (parent.left === child || parent.right === child))
    return true;

  return false;
}

function isUsedInControlTest(node, ancestors) {
  let child = node;

  for (let i = ancestors.length - 1; i >= 0; i--) {
    const parent = ancestors[i];
    if (!parent)
      return false;

    if ((parent.type === 'IfStatement' || parent.type === 'ConditionalExpression' || parent.type === 'WhileStatement' || parent.type === 'DoWhileStatement' || parent.type === 'ForStatement') && parent.test === child)
      return true;

    if (!isControlExpressionWrapper(parent, child))
      return false;

    child = parent;
  }

  return false;
}

function controlTestContext(node, ancestors) {
  let child = node;
  let negated = false;

  for (let i = ancestors.length - 1; i >= 0; i--) {
    const parent = ancestors[i];
    if (!parent)
      return null;

    if (parent.type === 'UnaryExpression' && parent.operator === '!' && parent.argument === child) {
      negated = !negated;
      child = parent;
      continue;
    }

    if (parent.type === 'IfStatement' && parent.test === child)
      return { ifNode: parent, negated };

    if (parent.type === 'LogicalExpression')
      return null;

    if (!isControlExpressionWrapper(parent, child))
      return null;

    child = parent;
  }

  return null;
}

function statementAbruptlyExits(node) {
  if (!node)
    return false;

  if (node.type === 'ThrowStatement' || node.type === 'ReturnStatement')
    return true;

  if (node.type === 'BlockStatement')
    return (node.body || []).some(statement => statementAbruptlyExits(statement));

  if (node.type === 'IfStatement')
    return statementAbruptlyExits(node.consequent) && statementAbruptlyExits(node.alternate);

  return false;
}

function followingStatementAbruptlyExits(ifNode, ancestors) {
  const ifIndex = ancestors.lastIndexOf(ifNode);
  if (ifIndex <= 0)
    return false;

  const parent = ancestors[ifIndex - 1];
  if (!parent || !Array.isArray(parent.body))
    return false;

  const statementIndex = parent.body.indexOf(ifNode);
  if (statementIndex < 0 || statementIndex >= parent.body.length - 1)
    return false;

  return statementAbruptlyExits(parent.body[statementIndex + 1]);
}

function statementPrecedesTargetInSameBlock(statement, ancestors, targetNode) {
  if (!statement || !targetNode)
    return false;

  const statementIndexInAncestors = ancestors.lastIndexOf(statement);
  if (statementIndexInAncestors <= 0)
    return false;

  const parent = ancestors[statementIndexInAncestors - 1];
  if (!parent || !Array.isArray(parent.body))
    return false;

  const statementIndex = parent.body.indexOf(statement);
  if (statementIndex < 0)
    return false;

  for (let i = statementIndex + 1; i < parent.body.length; i++) {
    if (branchContainsNode(parent.body[i], targetNode))
      return true;
  }

  return false;
}

function statementPrecedesGatedWorkInSameBlock(statement, ancestors, branchContainsGatedWork) {
  if (!statement || !branchContainsGatedWork)
    return false;

  const statementIndexInAncestors = ancestors.lastIndexOf(statement);
  if (statementIndexInAncestors <= 0)
    return false;

  const parent = ancestors[statementIndexInAncestors - 1];
  if (!parent || !Array.isArray(parent.body))
    return false;

  const statementIndex = parent.body.indexOf(statement);
  if (statementIndex < 0)
    return false;

  for (let i = 0; i < statementIndex; i++) {
    if (branchContainsGatedWork(parent.body[i]))
      return false;
  }

  for (let i = statementIndex + 1; i < parent.body.length; i++) {
    if (branchContainsGatedWork(parent.body[i]))
      return true;
  }

  return false;
}

function gatedWorkPrecedesStatementInSameBlock(statement, ancestors, branchContainsGatedWork) {
  if (!statement || !branchContainsGatedWork)
    return false;

  const path = (ancestors || []).concat(statement);
  for (let childIndex = path.length - 1; childIndex > 0; childIndex--) {
    const child = path[childIndex];
    const parent = path[childIndex - 1];
    if (!parent || !Array.isArray(parent.body))
      continue;

    const statementIndex = parent.body.indexOf(child);
    if (statementIndex < 0)
      continue;

    for (let i = 0; i < statementIndex; i++) {
      if (branchContainsGatedWork(parent.body[i]))
        return true;
    }
  }

  return false;
}

function branchContainsNode(branch, targetNode) {
  if (!branch || !targetNode)
    return false;

  let found = false;
  walk(branch, currentNode => {
    if (currentNode === targetNode) {
      found = true;
      return false;
    }

    return undefined;
  });

  return found;
}

function validationGatesControl(node, ancestors, predicateAllowsWhenTrue, branchContainsGatedWork, targetNode = null) {
  const context = controlTestContext(node, ancestors);
  if (!context)
    return false;

  const conditionAllows = context.negated ? !predicateAllowsWhenTrue : predicateAllowsWhenTrue;
  if (!conditionAllows) {
    const gatedWorkInRejectBranch = branchContainsGatedWork && branchContainsGatedWork(context.ifNode.consequent);
    const gatedWorkInAllowedElseBranch = branchContainsGatedWork && context.ifNode.alternate && branchContainsGatedWork(context.ifNode.alternate);
    if (gatedWorkInAllowedElseBranch) {
      if (!targetNode && gatedWorkPrecedesStatementInSameBlock(context.ifNode, ancestors, branchContainsGatedWork))
        return false;
      return statementAbruptlyExits(context.ifNode.consequent);
    }

    if (targetNode && !gatedWorkInRejectBranch && !statementPrecedesTargetInSameBlock(context.ifNode, ancestors, targetNode))
      return false;

    if (!targetNode && gatedWorkPrecedesStatementInSameBlock(context.ifNode, ancestors, branchContainsGatedWork))
      return false;

    return statementAbruptlyExits(context.ifNode.consequent) &&
      (!branchContainsGatedWork || !gatedWorkInRejectBranch);
  }

  const gatedWorkInAllowedBranch = branchContainsGatedWork && branchContainsGatedWork(context.ifNode.consequent);
  if (context.ifNode.alternate && statementAbruptlyExits(context.ifNode.alternate)) {
    if (!targetNode && gatedWorkPrecedesStatementInSameBlock(context.ifNode, ancestors, branchContainsGatedWork))
      return false;

    if (gatedWorkInAllowedBranch)
      return true;

    if (targetNode)
      return statementPrecedesTargetInSameBlock(context.ifNode, ancestors, targetNode);

    return statementPrecedesGatedWorkInSameBlock(context.ifNode, ancestors, branchContainsGatedWork);
  }

  return Boolean(
    branchContainsGatedWork &&
    gatedWorkInAllowedBranch &&
    followingStatementAbruptlyExits(context.ifNode, ancestors)
  );
}

function hasChannelAllowlistValidation(functionNode, channelName, scope, targetNode = null, moduleAliases = null) {
  let validated = false;
  const branchContainsTarget = branch => branchContainsNode(branch, targetNode);

  walkWithScope(functionNode, scope, (currentNode, parent, ancestors) => {
    const localAliases = localAliasesAt(functionNode, currentNode, ancestors, moduleAliases);

    if (currentNode.type === 'BinaryExpression' && ['===', '==', '!==', '!='].includes(currentNode.operator)) {
      const left = currentNode.left && currentNode.left.type === 'Identifier' ? currentNode.left.name : null;
      const right = currentNode.right && currentNode.right.type === 'Identifier' ? currentNode.right.name : null;
      const leftLiteral = typeof literalValue(currentNode.left, scope, localAliases) === 'string';
      const rightLiteral = typeof literalValue(currentNode.right, scope, localAliases) === 'string';

      if ((left === channelName && rightLiteral) || (right === channelName && leftLiteral)) {
        const predicateAllowsWhenTrue = currentNode.operator === '===' || currentNode.operator === '==';
        if (validationGatesControl(currentNode, ancestors, predicateAllowsWhenTrue, branchContainsTarget, targetNode)) {
          validated = true;
          return false;
        }
      }
    }

    if (currentNode.type === 'CallExpression' && currentNode.callee.type === 'MemberExpression') {
      const method = currentNode.callee.computed ? literalValue(currentNode.callee.property, scope, localAliases) : propertyName(currentNode.callee.property);
      if (!VALIDATION_CALL_METHODS.has(method))
        return undefined;

      if (!currentNode.arguments || currentNode.arguments.length === 0)
        return undefined;

      const firstArg = currentNode.arguments[0];
      if (firstArg.type === 'Identifier' && firstArg.name === channelName && isLiteralAllowlistReceiver(currentNode.callee.object, scope, localAliases)) {
        if (validationGatesControl(currentNode, ancestors, true, branchContainsTarget, targetNode)) {
          validated = true;
          return false;
        }
      }

      if (currentNode.callee.object.type === 'Identifier' && currentNode.callee.object.name === channelName) {
        if (typeof literalValue(firstArg, scope, localAliases) === 'string' && validationGatesControl(currentNode, ancestors, true, branchContainsTarget, targetNode)) {
          validated = true;
          return false;
        }
      }
    }

    return undefined;
  });

  return validated;
}

function senderExpressionKind(node, eventName, scope, localAliases = null) {
  if (!node)
    return null;

  const resolvedNode = resolveIdentifier(node, scope, localAliases);
  if (resolvedNode !== node)
    return senderExpressionKind(resolvedNode, eventName, scope, localAliases);

  if (resolvedNode.type === 'MemberExpression') {
    const label = expressionLabel(resolvedNode);
    if (label === `${eventName}.senderFrame.url`)
      return 'url';
    if (label === `${eventName}.senderFrame.origin`)
      return 'origin';

    const property = resolvedNode.computed ? literalValue(resolvedNode.property, scope, localAliases) : propertyName(resolvedNode.property);
    if (property === 'origin' && resolvedNode.object && resolvedNode.object.type === 'NewExpression' && resolvedNode.object.callee.type === 'Identifier' && resolvedNode.object.callee.name === 'URL') {
      const sourceNode = resolvedNode.object.arguments[0];
      const sourceKind = senderExpressionKind(sourceNode, eventName, scope, localAliases);
      if (sourceKind === 'url')
        return 'origin';
    }
  }

  if (resolvedNode.type === 'CallExpression' && resolvedNode.callee.type === 'MemberExpression') {
    const label = expressionLabel(resolvedNode.callee.object);
    const property = resolvedNode.callee.computed ? literalValue(resolvedNode.callee.property, scope, localAliases) : propertyName(resolvedNode.callee.property);
    if (label === `${eventName}.sender` && property === 'getURL')
      return 'url';
  }

  return null;
}

function weakSenderCheckLabel(node, eventName) {
  const label = expressionLabel(node);
  if (!label)
    return null;

  if (label === `${eventName}.processId`)
    return 'processId';
  if (label === `${eventName}.frameId`)
    return 'frameId';
  if (label === `${eventName}.sender.id`)
    return 'sender.id';
  if (label === `${eventName}.senderFrame.routingId`)
    return 'senderFrame.routingId';

  return null;
}

function branchContainsDangerousSink(branch, aliases, scope, localAliases) {
  let found = false;

  walk(branch, (currentNode, parent, ancestors) => {
    if (currentNode !== branch && isFunctionNode(currentNode))
      return false;

    const scopedLocalAliases = mergeAliasMaps(collectScopedLocalAliases(branch, currentNode, ancestors, aliases, localAliases), localAliases);
    if (currentNode.type === 'CallExpression' && dangerousSinkLabel(currentNode, aliases, scope, scopedLocalAliases)) {
      found = true;
      return false;
    }

    return undefined;
  });

  return found;
}

function branchContainsValidatedWork(branch, aliases, scope, localAliases) {
  if (branchContainsDangerousSink(branch, aliases, scope, localAliases))
    return true;

  let found = false;
  walk(branch, currentNode => {
    if (currentNode !== branch && isFunctionNode(currentNode))
      return false;

    if (currentNode.type === 'ReturnStatement' && currentNode.argument) {
      found = true;
      return false;
    }

    return undefined;
  });

  return found;
}

function senderAliasKind(node, senderAliases, scope, localAliases) {
  if (!node || node.type !== 'Identifier' || !senderAliases.has(node.name))
    return null;

  const alias = senderAliases.get(node.name);
  const resolvedNode = resolveIdentifier(node, scope, localAliases);
  return resolvedNode === alias.node ? alias.kind : null;
}

function analyzeSenderValidation(functionNode, eventName, scope, aliases, moduleAliases = null, targetNode = null) {
  const senderAliases = new Map();
  const validationEvidence = [];
  const weakChecks = [];
  const functionLocalAliases = mergeAliasMaps(collectLocalAliases(functionNode), moduleAliases);
  const branchContainsProtectedWork = targetNode ?
    (branch => branchContainsNode(branch, targetNode)) :
    (branch => branchContainsValidatedWork(branch, aliases, scope, functionLocalAliases));

  walkWithScope(functionNode, scope, (currentNode, parent, ancestors) => {
    const localAliases = localAliasesAt(functionNode, currentNode, ancestors, moduleAliases, aliases);

    if (currentNode.type === 'VariableDeclarator' && currentNode.id && currentNode.id.type === 'Identifier') {
      const senderKind = senderExpressionKind(currentNode.init, eventName, scope, localAliases);
      if (senderKind) {
        senderAliases.set(currentNode.id.name, {
          node: resolveIdentifier(currentNode.init, scope, localAliases),
          kind: senderKind
        });
        addUnique(validationEvidence, senderKind === 'origin' ? 'sender origin alias' : 'sender URL alias');
      }
    }

    if (currentNode.type === 'MemberExpression' || currentNode.type === 'CallExpression') {
      const weakLabel = weakSenderCheckLabel(currentNode.type === 'CallExpression' ? currentNode.callee : currentNode, eventName);
      if (weakLabel)
        addUnique(weakChecks, weakLabel);
    }

    return undefined;
  });

  let visible = false;

  walkWithScope(functionNode, scope, (currentNode, parent, ancestors) => {
    const localAliases = localAliasesAt(functionNode, currentNode, ancestors, moduleAliases, aliases);

    if (currentNode.type === 'BinaryExpression' && ['===', '==', '!==', '!='].includes(currentNode.operator)) {
      if (!isUsedInControlTest(currentNode, ancestors))
        return undefined;

      const leftKind = senderExpressionKind(currentNode.left, eventName, scope, localAliases);
      const rightKind = senderExpressionKind(currentNode.right, eventName, scope, localAliases);
      const leftAlias = senderAliasKind(currentNode.left, senderAliases, scope, localAliases);
      const rightAlias = senderAliasKind(currentNode.right, senderAliases, scope, localAliases);
      const leftLiteral = typeof literalValue(currentNode.left, scope, localAliases) === 'string';
      const rightLiteral = typeof literalValue(currentNode.right, scope, localAliases) === 'string';

      if ((leftKind || leftAlias) && rightLiteral) {
        const predicateAllowsWhenTrue = currentNode.operator === '===' || currentNode.operator === '==';
        if (validationGatesControl(currentNode, ancestors, predicateAllowsWhenTrue, branchContainsProtectedWork, targetNode)) {
          visible = true;
          addUnique(validationEvidence, (leftKind || leftAlias) === 'origin' ? 'sender origin compared to literal' : 'sender URL compared to literal');
          return false;
        }
      }

      if ((rightKind || rightAlias) && leftLiteral) {
        const predicateAllowsWhenTrue = currentNode.operator === '===' || currentNode.operator === '==';
        if (validationGatesControl(currentNode, ancestors, predicateAllowsWhenTrue, branchContainsProtectedWork, targetNode)) {
          visible = true;
          addUnique(validationEvidence, (rightKind || rightAlias) === 'origin' ? 'sender origin compared to literal' : 'sender URL compared to literal');
          return false;
        }
      }
    }

    if (currentNode.type === 'CallExpression' && currentNode.callee.type === 'MemberExpression') {
      const method = currentNode.callee.computed ? literalValue(currentNode.callee.property, scope, localAliases) : propertyName(currentNode.callee.property);
      if (!VALIDATION_CALL_METHODS.has(method))
        return undefined;

      const receiverKind = senderExpressionKind(currentNode.callee.object, eventName, scope, localAliases);
      const receiverAlias = senderAliasKind(currentNode.callee.object, senderAliases, scope, localAliases);
      const firstArg = currentNode.arguments && currentNode.arguments[0];
      const firstArgKind = senderExpressionKind(firstArg, eventName, scope, localAliases);
      const firstArgAlias = senderAliasKind(firstArg, senderAliases, scope, localAliases);

      if ((firstArgKind || firstArgAlias) && isLiteralAllowlistReceiver(currentNode.callee.object, scope, localAliases) && validationGatesControl(currentNode, ancestors, true, branchContainsProtectedWork, targetNode)) {
        visible = true;
        addUnique(validationEvidence, 'sender URL/origin checked against allowlist');
        return false;
      }

      if ((receiverKind || receiverAlias) && typeof literalValue(firstArg, scope, localAliases) === 'string' && validationGatesControl(currentNode, ancestors, true, branchContainsProtectedWork, targetNode)) {
        visible = true;
        addUnique(validationEvidence, 'sender URL/origin checked with string predicate');
        return false;
      }
    }

    return undefined;
  });

  return {
    visible,
    validationEvidence: uniqueSorted(validationEvidence),
    weakChecks: uniqueSorted(weakChecks)
  };
}

function dangerousSinkLabel(callNode, aliases, scope, localAliases = null) {
  const info = memberCallInfo(callNode, aliases, scope, localAliases);
  if (!info || !info.property)
    return null;

  if (info.objectPrimitive === 'fs' && DANGEROUS_FS_METHODS.has(info.property))
    return `fs.${info.property}`;

  if (info.objectPrimitive === 'shell' && DANGEROUS_SHELL_METHODS.has(info.property))
    return `shell.${info.property}`;

  if (info.objectPrimitive === 'child_process' && DANGEROUS_CHILD_PROCESS_METHODS.has(info.property))
    return `child_process.${info.property}`;

  return null;
}

function keywordSinkLabels(functionNode) {
  return [];
}

function analyzeFunctionBody(functionNode, aliases, scope, moduleAliases = null) {
  const params = new Set(parameterNames(functionNode.params));
  const parameterAliases = new Set(params);
  const summary = {
    rawIpcExposures: [],
    nodePrimitiveExposures: [],
    arbitraryChannelForwards: [],
    literalChannels: [],
    dangerousWrappers: [],
    dangerousSinks: [],
    rawIpcExposureNodes: [],
    nodePrimitiveExposureNodes: [],
    arbitraryChannelForwardNodes: [],
    dangerousWrapperNodes: [],
    dangerousSinkNodes: [],
    dangerousSinkLabels: new Map()
  };

  walkWithScope(functionNode, scope, (currentNode, parent, ancestors) => {
    const localAliases = localAliasesAt(functionNode, currentNode, ancestors, moduleAliases, aliases);

    if (currentNode.type === 'VariableDeclarator' &&
        currentNode.id &&
        currentNode.id.type === 'Identifier' &&
        referencesIdentifier(currentNode.init, parameterAliases, scope, localAliases)) {
      parameterAliases.add(currentNode.id.name);
    }

    return undefined;
  });

  walkWithScope(functionNode, scope, (currentNode, parent, ancestors) => {
    const localAliases = localAliasesAt(functionNode, currentNode, ancestors, moduleAliases, aliases);

    if (currentNode.type === 'ReturnStatement') {
      const primitive = primitiveLabel(currentNode.argument, aliases, scope, localAliases);
      if (primitive === 'ipcRenderer') {
        addUnique(summary.rawIpcExposures, 'ipcRenderer');
        summary.rawIpcExposureNodes.push(currentNode.argument);
      }
      if (primitive && primitive !== 'ipcRenderer') {
        addUnique(summary.nodePrimitiveExposures, primitive);
        summary.nodePrimitiveExposureNodes.push(currentNode.argument);
      }
      return undefined;
    }

    if (currentNode.type !== 'CallExpression')
      return undefined;

    const info = memberCallInfo(currentNode, aliases, scope, localAliases);
    const sinkLabel = dangerousSinkLabel(currentNode, aliases, scope, localAliases);
    if (sinkLabel) {
      addUnique(summary.dangerousSinks, sinkLabel);
      summary.dangerousSinkNodes.push(currentNode);
      summary.dangerousSinkLabels.set(currentNode, sinkLabel);
      if (parameterAliases.size > 0 && currentNode.arguments.some(argument => referencesIdentifier(argument, parameterAliases, scope, localAliases))) {
        addUnique(summary.dangerousWrappers, sinkLabel);
        summary.dangerousWrapperNodes.push(currentNode);
      }
    }

    if (!info || !IPC_FORWARD_METHODS.has(info.property) || info.objectPrimitive !== 'ipcRenderer')
      return undefined;

    const channelNode = currentNode.arguments[0];
    const literalChannel = literalValue(channelNode, scope, localAliases);
    if (typeof literalChannel === 'string') {
      addUnique(summary.literalChannels, literalChannel);
      return undefined;
    }

    if (channelNode && channelNode.type === 'Identifier' && parameterAliases.has(channelNode.name) && !hasChannelAllowlistValidation(functionNode, channelNode.name, scope, currentNode, moduleAliases)) {
      addUnique(summary.arbitraryChannelForwards, info.property);
      summary.arbitraryChannelForwardNodes.push(currentNode);
    }

    return undefined;
  });

  keywordSinkLabels(functionNode).forEach(label => addUnique(summary.dangerousSinks, label));

  return summary;
}

function analyzeExposedValue(node, methodName, aliases, scope, moduleAliases = null) {
  const resolvedNode = resolveIdentifier(node, scope, moduleAliases);
  const primitive = primitiveLabel(node, aliases, scope, moduleAliases);
  const summary = {
    rawIpcExposures: [],
    nodePrimitiveExposures: [],
    arbitraryChannelForwards: [],
    literalChannels: [],
    dangerousWrappers: [],
    rawIpcExposureNodes: [],
    nodePrimitiveExposureNodes: [],
    arbitraryChannelForwardNodes: [],
    dangerousWrapperNodes: []
  };

  if (primitive === 'ipcRenderer') {
    addUnique(summary.rawIpcExposures, 'ipcRenderer');
    summary.rawIpcExposureNodes.push(node);
  }
  if (primitive && primitive !== 'ipcRenderer') {
    addUnique(summary.nodePrimitiveExposures, primitive);
    summary.nodePrimitiveExposureNodes.push(node);
  }

  if (resolvedNode && resolvedNode.type === 'MemberExpression') {
    const memberObject = primitiveLabel(resolvedNode.object, aliases, scope, moduleAliases);
    const property = resolvedNode.computed ? literalValue(resolvedNode.property, scope, moduleAliases) : propertyName(resolvedNode.property);

    if (memberObject === 'ipcRenderer' && IPC_FORWARD_METHODS.has(property)) {
      addUnique(summary.arbitraryChannelForwards, property);
      summary.arbitraryChannelForwardNodes.push(node);
    }

    if (memberObject === 'shell' && DANGEROUS_SHELL_METHODS.has(property)) {
      addUnique(summary.dangerousWrappers, `shell.${property}`);
      summary.dangerousWrapperNodes.push(node);
    }

    if (memberObject === 'fs' && DANGEROUS_FS_METHODS.has(property)) {
      addUnique(summary.dangerousWrappers, `fs.${property}`);
      summary.dangerousWrapperNodes.push(node);
    }

    if (memberObject === 'child_process' && DANGEROUS_CHILD_PROCESS_METHODS.has(property)) {
      addUnique(summary.dangerousWrappers, `child_process.${property}`);
      summary.dangerousWrapperNodes.push(node);
    }
  }

  if (isFunctionNode(resolvedNode)) {
    const functionSummary = analyzeFunctionBody(resolvedNode, aliases, scope, moduleAliases);
    functionSummary.rawIpcExposures.forEach(value => addUnique(summary.rawIpcExposures, value));
    functionSummary.nodePrimitiveExposures.forEach(value => addUnique(summary.nodePrimitiveExposures, value));
    functionSummary.arbitraryChannelForwards.forEach(value => addUnique(summary.arbitraryChannelForwards, value));
    functionSummary.literalChannels.forEach(value => addUnique(summary.literalChannels, value));
    functionSummary.dangerousWrappers.forEach(value => addUnique(summary.dangerousWrappers, value));
    summary.rawIpcExposureNodes.push(...functionSummary.rawIpcExposureNodes);
    summary.nodePrimitiveExposureNodes.push(...functionSummary.nodePrimitiveExposureNodes);
    summary.arbitraryChannelForwardNodes.push(...functionSummary.arbitraryChannelForwardNodes);
    summary.dangerousWrapperNodes.push(...functionSummary.dangerousWrapperNodes);
  }

  summary.methodName = methodName;
  summary.line = lineColumn(node).line;
  summary.column = lineColumn(node).column;
  return summary;
}

function bridgeRecordKey(file, line, column, globalName) {
  return `preload_bridge|${file}|${line}|${column}|${globalName || 'dynamic'}`;
}

function ipcChannelRecordKey(file, line, column, handlerType, channel) {
  return `ipc_channel|${file}|${line}|${column}|${handlerType}|${channel || 'dynamic'}`;
}

function sourceFileKey(file) {
  return `source_file|${file}`;
}

function createRecord(records, record) {
  records.push(record);
  return record;
}

function createRelationship(relationships, relationship) {
  relationships.push(relationship);
  return relationship;
}

function buildIssue(file, fileClassification, content, node, id, description, severityValue, confidenceValue, properties) {
  const location = lineColumn(node);
  const check = FINDING_CHECK_BY_ID.get(id);
  const firstLineSample = sampleAt(content, 1);
  const matchedLineSample = sampleAt(content, location.line);
  return {
    file,
    sample: sampleAt(content, location.line),
    location,
    id,
    description,
    properties,
    severity: severityValue,
    confidence: confidenceValue,
    manualReview: true,
    shortenedURL: 'https://github.com/doyensec/electronegativity/wiki',
    visibility: check ? isDisabledByInlineComment(firstLineSample, matchedLineSample, check, sourceTypes.JAVASCRIPT) : { excludesGlobal: [], inlineDisabled: false, globalCheckDisabled: false },
    constructorName: check ? check.constructor.name : id,
    fileClassification
  };
}

function buildIssueForEvidence(file, fileClassification, content, fallbackNode, evidenceNodes, id, description, severityValue, confidenceValue, properties) {
  const nodes = (evidenceNodes || []).filter(Boolean);
  if (nodes.length === 0 && fallbackNode)
    nodes.push(fallbackNode);

  const issues = nodes.map(node => buildIssue(file, fileClassification, content, node, id, description, severityValue, confidenceValue, properties));
  const visibleIssue = issues.find(issue => !issue.visibility || !issue.visibility.inlineDisabled);
  return visibleIssue || issues[0];
}

function issueProperties(baseProperties) {
  return Object.assign({
    issueType: 'finding',
    issueClassification: 'finding'
  }, baseProperties);
}

export class PreloadIpcCollector {
  constructor(options = {}) {
    this.records = [];
    this.relationships = [];
    this.bridgeExposures = [];
    this.ipcChannels = [];
    this.enabledFindingIds = new Set(FINDING_CHECK_IDS);

    if (options.customScan && options.customScan.length > 0) {
      this.enabledFindingIds = new Set();
      options.customScan.forEach(name => {
        const id = phase6CheckIdForName(name);
        if (id)
          this.enabledFindingIds.add(id);
      });
    }

    (options.excludeFromScan || []).forEach(name => {
      const id = phase6CheckIdForName(name);
      if (id)
        this.enabledFindingIds.delete(id);
    });
  }

  collect(file, type, data, content, fileClassification) {
    if (type !== sourceTypes.JAVASCRIPT || !data)
      return;

    const program = data.type === 'File' ? data.program : data;
    const scope = data.Scope;
    const aliases = collectAliases(program);
    const moduleAliases = collectModuleAliases(program, aliases);

    walkWithScope(program, scope, (node, parent, ancestors) => {
      if (node.type !== 'CallExpression')
        return undefined;

      const scopedAliases = scopedAliasesAtCall(aliases, moduleAliases, node, ancestors);

      if (isContextBridgeExposeCall(node.callee, scopedAliases.aliases)) {
        this.collectBridgeExposure(file, node, content, scope, scopedAliases.aliases, scopedAliases.moduleAliases, fileClassification);
        return undefined;
      }

      const handlerType = ipcHandlerType(node.callee, scopedAliases.aliases);
      if (handlerType)
        this.collectIpcHandler(file, node, content, scope, scopedAliases.aliases, scopedAliases.moduleAliases, handlerType, fileClassification);

      return undefined;
    });
  }

  collectBridgeExposure(file, node, content, scope, aliases, moduleAliases, fileClassification) {
    const globalName = literalValue(node.arguments[0], scope, moduleAliases);
    const exposureNode = resolveIdentifier(node.arguments[1], scope, moduleAliases);
    const exposureLine = lineColumn(node);
    const methods = [];
    const rawIpcExposures = [];
    const nodePrimitiveExposures = [];
    const arbitraryChannelForwards = [];
    const dangerousWrappers = [];
    const literalChannels = [];
    const rawIpcExposureNodes = [];
    const nodePrimitiveExposureNodes = [];
    const arbitraryChannelForwardNodes = [];
    const dangerousWrapperNodes = [];

    if (exposureNode && exposureNode.type === 'ObjectExpression') {
      (exposureNode.properties || []).forEach(property => {
        const propertyValue = objectPropertyValue(property);
        if (!propertyValue)
          return;

        const methodName = propertyName(property.key);
        addUnique(methods, methodName);
        const summary = analyzeExposedValue(propertyValue, methodName, aliases, scope, moduleAliases);
        summary.rawIpcExposures.forEach(value => addUnique(rawIpcExposures, value));
        summary.nodePrimitiveExposures.forEach(value => addUnique(nodePrimitiveExposures, value));
        summary.arbitraryChannelForwards.forEach(value => addUnique(arbitraryChannelForwards, methodName || value));
        summary.dangerousWrappers.forEach(value => addUnique(dangerousWrappers, `${methodName}: ${value}`));
        summary.literalChannels.forEach(value => addUnique(literalChannels, value));
        rawIpcExposureNodes.push(...summary.rawIpcExposureNodes);
        nodePrimitiveExposureNodes.push(...summary.nodePrimitiveExposureNodes);
        arbitraryChannelForwardNodes.push(...summary.arbitraryChannelForwardNodes);
        dangerousWrapperNodes.push(...summary.dangerousWrapperNodes);
      });
    } else {
      const summary = analyzeExposedValue(exposureNode, globalName, aliases, scope, moduleAliases);
      summary.rawIpcExposures.forEach(value => addUnique(rawIpcExposures, value));
      summary.nodePrimitiveExposures.forEach(value => addUnique(nodePrimitiveExposures, value));
      summary.arbitraryChannelForwards.forEach(value => addUnique(arbitraryChannelForwards, globalName || value));
      summary.dangerousWrappers.forEach(value => addUnique(dangerousWrappers, `${globalName || 'bridge'}: ${value}`));
      summary.literalChannels.forEach(value => addUnique(literalChannels, value));
      rawIpcExposureNodes.push(...summary.rawIpcExposureNodes);
      nodePrimitiveExposureNodes.push(...summary.nodePrimitiveExposureNodes);
      arbitraryChannelForwardNodes.push(...summary.arbitraryChannelForwardNodes);
      dangerousWrapperNodes.push(...summary.dangerousWrapperNodes);
    }

    const bridgeRecord = createRecord(this.records, {
      key: bridgeRecordKey(file, exposureLine.line, exposureLine.column, globalName),
      entity_type: 'preload_bridge',
      title: `Preload bridge exposure: ${globalName || 'dynamic'}`,
      file,
      line: exposureLine.line,
      column: exposureLine.column,
      global_name: globalName || null,
      methods: uniqueSorted(methods),
      raw_ipc_exposed: rawIpcExposures.length > 0,
      node_primitives_exposed: uniqueSorted(nodePrimitiveExposures),
      arbitrary_channel_methods: uniqueSorted(arbitraryChannelForwards),
      dangerous_wrappers: uniqueSorted(dangerousWrappers),
      literal_ipc_channels: uniqueSorted(literalChannels)
    });
    createRelationship(this.relationships, {
      relationship_type: 'declared_in',
      from_key: bridgeRecord.key,
      to_key: sourceFileKey(file),
      file,
      line: exposureLine.line,
      column: exposureLine.column
    });

    this.bridgeExposures.push({
      file,
      fileClassification,
      content,
      node,
      record: bridgeRecord,
      globalName: globalName || null,
      rawIpcExposures: uniqueSorted(rawIpcExposures),
      nodePrimitiveExposures: uniqueSorted(nodePrimitiveExposures),
      arbitraryChannelForwards: uniqueSorted(arbitraryChannelForwards),
      dangerousWrappers: uniqueSorted(dangerousWrappers),
      literalChannels: uniqueSorted(literalChannels),
      rawIpcExposureNodes,
      nodePrimitiveExposureNodes,
      arbitraryChannelForwardNodes,
      dangerousWrapperNodes
    });
  }

  collectIpcHandler(file, node, content, scope, aliases, moduleAliases, handlerType, fileClassification) {
    const channel = literalValue(node.arguments[0], scope, moduleAliases);
    const handlerNode = resolveIdentifier(node.arguments[1], scope, moduleAliases);
    if (!isFunctionNode(handlerNode))
      return;

    const params = parameterNames(handlerNode.params);
    const eventName = params[0];
    const validation = eventName ? analyzeSenderValidation(handlerNode, eventName, scope, aliases, moduleAliases) : { visible: false, validationEvidence: [], weakChecks: [] };
    const functionSummary = analyzeFunctionBody(handlerNode, aliases, scope, moduleAliases);
    const unvalidatedDangerousSinkNodes = eventName ?
      functionSummary.dangerousSinkNodes.filter(sinkNode => !analyzeSenderValidation(handlerNode, eventName, scope, aliases, moduleAliases, sinkNode).visible) :
      functionSummary.dangerousSinkNodes.slice();
    const dangerousSinksWithoutSenderValidation = uniqueSorted(
      unvalidatedDangerousSinkNodes.map(sinkNode => functionSummary.dangerousSinkLabels.get(sinkNode))
    );
    const handlerLine = lineColumn(node);
    const channelRecord = createRecord(this.records, {
      key: ipcChannelRecordKey(file, handlerLine.line, handlerLine.column, handlerType, channel),
      entity_type: 'ipc_channel',
      title: `IPC channel ${channel || 'dynamic'}`,
      file,
      line: handlerLine.line,
      column: handlerLine.column,
      channel: channel || null,
      handler_type: handlerType,
      visible_sender_validation: validation.visible,
      sender_validation_evidence: validation.validationEvidence,
      weak_sender_checks: validation.weakChecks,
      dangerous_sinks: uniqueSorted(functionSummary.dangerousSinks)
    });
    createRelationship(this.relationships, {
      relationship_type: 'declared_in',
      from_key: channelRecord.key,
      to_key: sourceFileKey(file),
      file,
      line: handlerLine.line,
      column: handlerLine.column
    });

    this.ipcChannels.push({
      file,
      fileClassification,
      content,
      node,
      channel: channel || null,
      handlerType,
      validation,
      dangerousSinks: uniqueSorted(functionSummary.dangerousSinks),
      dangerousSinkNodes: functionSummary.dangerousSinkNodes,
      dangerousSinksWithoutSenderValidation,
      unvalidatedDangerousSinkNodes
    });
  }

  buildFindings() {
    const issues = [];
    const dangerousChannels = this.ipcChannels.filter(channel => channel.dangerousSinks.length > 0);

    this.bridgeExposures.forEach(exposure => {
      if (exposure.rawIpcExposures.length > 0) {
        issues.push(buildIssueForEvidence(
          exposure.file,
          exposure.fileClassification,
          exposure.content,
          exposure.node,
          exposure.rawIpcExposureNodes,
          'PRELOAD_RAW_IPC_EXPOSURE',
          'Preload bridge exposes raw ipcRenderer access to the renderer',
          severity.HIGH,
          confidence.CERTAIN,
          issueProperties({
            electronComponent: 'preload',
            trustBoundary: 'renderer_to_preload_bridge',
            affectedChannel: exposure.globalName,
            confidenceReasons: ['direct contextBridge exposure', 'raw ipcRenderer object exposed'],
            nextAgentHint: 'Trace whether untrusted renderer content can call this bridge directly.'
          })
        ));
      }

      if (exposure.nodePrimitiveExposures.length > 0) {
        issues.push(buildIssueForEvidence(
          exposure.file,
          exposure.fileClassification,
          exposure.content,
          exposure.node,
          exposure.nodePrimitiveExposureNodes,
          'PRELOAD_NODE_PRIMITIVE_EXPOSURE',
          'Preload bridge exposes Node.js primitives or privileged Electron modules to the renderer',
          severity.HIGH,
          confidence.FIRM,
          issueProperties({
            electronComponent: 'preload',
            trustBoundary: 'renderer_to_preload_bridge',
            affectedChannel: exposure.globalName,
            confidenceReasons: ['direct contextBridge exposure', `exposed primitives: ${exposure.nodePrimitiveExposures.join(', ')}`],
            nextAgentHint: 'Review whether any remote or untrusted renderer content can reach this exposed API.'
          })
        ));
      }

      if (exposure.arbitraryChannelForwards.length > 0) {
        issues.push(buildIssueForEvidence(
          exposure.file,
          exposure.fileClassification,
          exposure.content,
          exposure.node,
          exposure.arbitraryChannelForwardNodes,
          'PRELOAD_ARBITRARY_CHANNEL_FORWARD',
          'Preload bridge forwards caller-controlled IPC channel names to ipcRenderer',
          severity.HIGH,
          confidence.FIRM,
          issueProperties({
            electronComponent: 'preload',
            trustBoundary: 'renderer_to_main_ipc',
            affectedChannel: exposure.globalName,
            confidenceReasons: ['contextBridge wrapper forwards caller-controlled IPC channel names'],
            nextAgentHint: 'Link the exposed forwarding method to reachable ipcMain handlers and renderer entrypoints.'
          })
        ));
      }

      if (exposure.dangerousWrappers.length > 0) {
        issues.push(buildIssueForEvidence(
          exposure.file,
          exposure.fileClassification,
          exposure.content,
          exposure.node,
          exposure.dangerousWrapperNodes,
          'PRELOAD_DANGEROUS_API_WRAPPER',
          'Preload bridge wraps dangerous native-capability APIs with caller-controlled arguments',
          severity.HIGH,
          confidence.FIRM,
          issueProperties({
            electronComponent: 'preload',
            trustBoundary: 'renderer_to_preload_bridge',
            affectedChannel: exposure.globalName,
            confidenceReasons: [`dangerous wrappers: ${exposure.dangerousWrappers.join(', ')}`],
            nextAgentHint: 'Review whether renderer-controlled data reaches privileged filesystem, shell, or process APIs.'
          })
        ));
      }

      if (exposure.arbitraryChannelForwards.length > 0) {
        dangerousChannels.forEach(channel => {
          if (!channel.channel)
            return;

          issues.push(buildIssue(
            exposure.file,
            exposure.fileClassification,
            exposure.content,
            exposure.node,
            'IPC_ARBITRARY_FORWARDING_TO_DANGEROUS_CHANNEL',
            `Preload bridge arbitrary IPC forwarding can reach dangerous main-process channel "${channel.channel}"`,
            severity.HIGH,
            confidence.FIRM,
            issueProperties({
              electronComponent: 'ipc',
              trustBoundary: 'renderer_to_main_ipc',
              affectedChannel: channel.channel,
              confidenceReasons: ['generic preload channel forwarding', `dangerous handler sinks: ${channel.dangerousSinks.join(', ')}`],
              nextAgentHint: 'Verify whether renderer code can invoke this bridge and reach the linked ipcMain handler.'
            })
          ));
        });
      }
    });

    this.ipcChannels.forEach(channel => {
      if (!channel.validation.visible) {
        issues.push(buildIssue(
          channel.file,
          channel.fileClassification,
          channel.content,
          channel.node,
          'IPC_SENDER_VALIDATION_MISSING',
          'IPC handler lacks visible sender URL/origin validation',
          severity.MEDIUM,
          confidence.FIRM,
          issueProperties({
            electronComponent: 'ipc',
            trustBoundary: 'renderer_to_main_ipc',
            affectedChannel: channel.channel,
            confidenceReasons: ['ipcMain handler registered without visible sender allowlist'],
            nextAgentHint: 'Review which renderers can reach this channel and whether sender origin checks are expected.'
          })
        ));
      }

      if (channel.dangerousSinksWithoutSenderValidation.length > 0) {
        issues.push(buildIssueForEvidence(
          channel.file,
          channel.fileClassification,
          channel.content,
          channel.node,
          channel.unvalidatedDangerousSinkNodes,
          'IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION',
          'IPC handler reaches dangerous sinks without visible sender URL/origin validation',
          severity.HIGH,
          confidence.FIRM,
          issueProperties({
            electronComponent: 'ipc',
            trustBoundary: 'renderer_to_main_ipc',
            affectedChannel: channel.channel,
            confidenceReasons: [`dangerous sinks: ${channel.dangerousSinksWithoutSenderValidation.join(', ')}`, 'no visible sender allowlist'],
            nextAgentHint: 'Trace renderer reachability to this IPC channel before triage.'
          })
        ));
      }
    });

    return issues.filter(issue => this.enabledFindingIds.has(issue.id));
  }

  buildAuditResults() {
    return {
      issues: this.buildFindings(),
      componentInventory: {
        records: this.records,
        relationships: this.relationships
      }
    };
  }
}
