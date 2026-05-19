import fs from 'fs';
import path from 'path';
import logger from 'winston';
import { LoaderFile } from '../src/loader';
import { Parser } from '../src/parser';
import { Finder } from '../src/finder';
import { GlobalChecks } from '../src/finder';
import _i18n from '../src/locales/i18n.js';

_i18n();

let chai = require('chai');
let should = chai.should();

logger.addColors({
  debug : 'green',
  info : 'cyan',
  silly : 'magenta',
  warn : 'yellow',
  error : 'red'
});

logger.remove(logger.transports.Console);
logger.add(logger.transports.Console, {colorize : true, level : 'silly'});

let check_tests = "test/checks/AtomicChecks";

async function findSnippet(source, checkId, electronVersion = null) {
  const filename = path.join(check_tests, `phase3_${checkId.toLowerCase()}.js`);
  const parser = new Parser(false, true);
  const [type, data, content] = parser.parse(filename, Buffer.from(source));
  const finder = new Finder(null, null, null);
  const classification = parser.getFileClassification(filename);
  return finder.find(filename, data, type, content, [checkId], electronVersion, classification);
}

async function findMarkup(source, checkId, electronVersion = null) {
  const filename = path.join(check_tests, `phase3_${checkId.toLowerCase()}.html`);
  const parser = new Parser(false, true);
  const [type, data, content] = parser.parse(filename, Buffer.from(source));
  const finder = new Finder(null, null, null);
  const classification = parser.getFileClassification(filename);
  return finder.find(filename, data, type, content, [checkId], electronVersion, classification);
}

async function findJson(source, checkId, electronVersion = null) {
  const filename = path.join(check_tests, `phase3_${checkId.toLowerCase()}.json`);
  const parser = new Parser(false, true);
  const [type, data, content] = parser.parse(filename, Buffer.from(source));
  const finder = new Finder(null, null, null);
  const classification = parser.getFileClassification(filename);
  return finder.find(filename, data, type, content, [checkId], electronVersion, classification);
}

describe('Finder file classification', () => {
  it('attaches classification to emitted issues', async () => {
    const file = path.join(check_tests, 'NODE_INTEGRATION_JS_CHECK_13_1.js');
    let loader = new LoaderFile();
    loader.load(file);
    let filename = [...loader.list_files][0];
    let parser = new Parser(false, true);
    const [type, data, content] = parser.parse(filename, loader.load_buffer(filename));
    let finder = new Finder(null, null, null);
    let classification = {
      is_bundle: false,
      is_minified: false,
      parser_status: 'ok'
    };

    let result = await finder.find(filename, data, type, content, ['NODE_INTEGRATION_JS_CHECK'], null, classification);

    result.length.should.be.above(0);
    result[0].fileClassification.should.equal(classification);
  });

  it('keeps HTML checks working after the finder match signature expansion', async () => {
    const issues = await findMarkup('<webview src=\"https://example.com\" nodeintegration></webview>', 'NODE_INTEGRATION_HTML_CHECK');

    issues.length.should.equal(1);
    issues[0].fileClassification.parser_status.should.equal('ok');
  });

  it('keeps JSON checks working after the finder match signature expansion', async () => {
    const issues = await findJson('{\"dependencies\":{\"electron\":\"^20.0.0\"}}', 'ELECTRON_VERSION_JSON_CHECK');

    issues.length.should.equal(1);
    issues[0].fileClassification.parser_status.should.equal('ok');
  });

  it('classifies Electron version package.json checks as inventory while preserving version metadata', async () => {
    const issues = await findJson('{\"dependencies\":{\"electron\":\"^20.0.0\"}}', 'ELECTRON_VERSION_JSON_CHECK');

    issues.length.should.equal(1);
    issues[0].severity.name.should.equal('INFORMATIONAL');
    issues[0].manualReview.should.equal(false);
    issues[0].properties.issueType.should.equal('finding');
    issues[0].properties.issueClassification.should.equal('inventory');
    issues[0].properties.versionNumber.should.equal('20.0.0');
  });

  it('classifies disabled security warning flags as hardening in JSON and JS checks', async () => {
    const jsonIssues = await findJson(`{
      "scripts": {
        "start": "ELECTRON_DISABLE_SECURITY_WARNINGS=1 electron ."
      }
    }`, 'SECURITY_WARNINGS_DISABLED_JSON_CHECK');
    const jsIssues = await findSnippet('process.env.ELECTRON_DISABLE_SECURITY_WARNINGS = true;', 'SECURITY_WARNINGS_DISABLED_JS_CHECK');

    jsonIssues.length.should.equal(1);
    jsonIssues[0].severity.name.should.equal('INFORMATIONAL');
    jsonIssues[0].properties.issueType.should.equal('finding');
    jsonIssues[0].properties.issueClassification.should.equal('hardening');

    jsIssues.length.should.equal(1);
    jsIssues[0].severity.name.should.equal('INFORMATIONAL');
    jsIssues[0].properties.issueType.should.equal('finding');
    jsIssues[0].properties.issueClassification.should.equal('hardening');
  });
});

describe('Finder version-aware defaults', () => {
  it('treats missing nodeIntegration as insecure before Electron 5 and hardening afterwards', async () => {
    const source = 'new BrowserWindow({ webPreferences: {} });';
    const oldIssues = await findSnippet(source, 'NODE_INTEGRATION_JS_CHECK', '4.0.0');
    const modernIssues = await findSnippet(source, 'NODE_INTEGRATION_JS_CHECK', '5.0.0');

    oldIssues.length.should.equal(1);
    oldIssues[0].severity.name.should.equal('HIGH');
    oldIssues[0].manualReview.should.equal(false);
    oldIssues[0].properties.issueType.should.equal('finding');
    oldIssues[0].properties.issueClassification.should.equal('finding');
    oldIssues[0].properties.versionContext.defaultBehavior.should.equal('node_integration_default_true');

    modernIssues.length.should.equal(1);
    modernIssues[0].severity.name.should.equal('INFORMATIONAL');
    modernIssues[0].manualReview.should.equal(false);
    modernIssues[0].properties.issueType.should.equal('finding');
    modernIssues[0].properties.issueClassification.should.equal('hardening');
    modernIssues[0].properties.versionContext.defaultBehavior.should.equal('node_integration_default_false');
  });

  it('treats missing contextIsolation as insecure before Electron 12 and hardening afterwards', async () => {
    const source = 'new BrowserWindow({ webPreferences: {} });';
    const oldIssues = await findSnippet(source, 'CONTEXT_ISOLATION_JS_CHECK', '11.0.0');
    const modernIssues = await findSnippet(source, 'CONTEXT_ISOLATION_JS_CHECK', '12.0.0');

    oldIssues.length.should.equal(1);
    oldIssues[0].severity.name.should.equal('HIGH');
    oldIssues[0].manualReview.should.equal(false);
    oldIssues[0].properties.versionContext.defaultBehavior.should.equal('context_isolation_default_false');

    modernIssues.length.should.equal(1);
    modernIssues[0].severity.name.should.equal('INFORMATIONAL');
    modernIssues[0].manualReview.should.equal(false);
    modernIssues[0].properties.issueClassification.should.equal('hardening');
    modernIssues[0].properties.versionContext.defaultBehavior.should.equal('context_isolation_default_true');
  });

  it('treats missing sandbox as insecure before Electron 20 and hardening afterwards', async () => {
    const source = 'new BrowserWindow({ webPreferences: {} });';
    const oldIssues = await findSnippet(source, 'SANDBOX_JS_CHECK', '19.0.0');
    const modernIssues = await findSnippet(source, 'SANDBOX_JS_CHECK', '20.0.0');

    oldIssues.length.should.equal(1);
    oldIssues[0].severity.name.should.equal('MEDIUM');
    oldIssues[0].manualReview.should.equal(false);
    oldIssues[0].properties.versionContext.defaultBehavior.should.equal('sandbox_default_false');

    modernIssues.length.should.equal(1);
    modernIssues[0].severity.name.should.equal('INFORMATIONAL');
    modernIssues[0].manualReview.should.equal(false);
    modernIssues[0].properties.issueClassification.should.equal('hardening');
    modernIssues[0].properties.versionContext.defaultBehavior.should.equal('sandbox_default_true');
  });

  it('keeps explicit insecure settings classified as findings when the default is secure', async () => {
    const source = 'new BrowserWindow({ webPreferences: { contextIsolation: false } });';
    const issues = await findSnippet(source, 'CONTEXT_ISOLATION_JS_CHECK', '12.0.0');

    issues.length.should.equal(1);
    issues[0].severity.name.should.equal('HIGH');
    issues[0].properties.issueType.should.equal('finding');
    issues[0].properties.issueClassification.should.equal('finding');
  });

  it('represents unknown defaults explicitly instead of pretending a precise Electron version', async () => {
    const source = 'new BrowserWindow({ webPreferences: {} });';
    const issues = await findSnippet(source, 'CONTEXT_ISOLATION_JS_CHECK', null);

    issues.length.should.equal(1);
    issues[0].severity.name.should.equal('LOW');
    issues[0].manualReview.should.equal(true);
    should.equal(issues[0].properties.versionContext.electronVersion, null);
    issues[0].properties.versionContext.defaultBehavior.should.equal('context_isolation_default_unknown');
  });
});

describe('Finder', () => {
  let finder = new Finder(null, null, '4..8');

  // Load all test files
  let loader = new LoaderFile();
  let list = fs.readdirSync(check_tests);
  for (let file of list) {
    loader.load(path.join(check_tests, file));
  }
  let filenames = [...loader.list_files];

  // Parse all files and ...
  let parsers = [new Parser(false, true), new Parser(true, true), new Parser(true, false), new Parser(false, false)];
  for (let parser of parsers) {
    let testcases = new Map();

    for (let file of filenames) {
      const [type, data, content] = parser.parse(file, loader.load_buffer(file));
      let split = path.basename(file.substr(0, file.lastIndexOf('.'))).split('_');
      let num_issues = +split.pop();
      split.pop();
      let check = split.join("_").toUpperCase();

      if (!testcases.has(check)) {
        testcases.set(check, []);
      }
      testcases.get(check).push([file, type, data, num_issues, content]);
    }

    // For each ...
    for (let check of [...testcases.keys()]) {
      for (let [file, type, data, num_issues, content] of testcases.get(check)) {
        it('Finds ' + num_issues + ' issue(s) in ' + path.basename(file), async () => {
          let result = await finder.find(file, data, type, content);
          
          // Adjust visibility
          result = result.filter(i => !i.hasOwnProperty('visibility') || (!i.visibility.inlineDisabled && !i.visibility.globalCheckDisabled));
          
          result.filter(r => {return r.id === check;}).length.should.equal(num_issues);
        }).timeout(8000);
      }
    }
  }
});
