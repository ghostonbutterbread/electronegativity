import cliProgress from 'cli-progress';
import Table from 'cli-table3';
import chalk from 'chalk';
import logger from 'winston';
import fs from 'fs';
import path from 'path';

import _i18n from './locales/i18n';
import { LoaderFile, LoaderAsar, LoaderDirectory } from './loader';
import { Parser, parseErrorRecord } from './parser';
import { Finder } from './finder';
import { GlobalChecks, severity, confidence } from './finder';
import { RendererInventoryCollector, PreloadIpcCollector, StaticTrustCollector, isPreloadIpcAuditCheckName, isStaticTrustAuditCheckName } from './inventory';
import { buildFindings, buildHypotheses, buildInventory, buildRunMetadata, buildSarifDocument, contextPacketFilename, writeOutputDirectory } from './output';
import { createFuseContext, createVersionContext } from './util/electron_context';
import { extension, input_exists, is_directory, writeIssues, getRelativePath } from './util';

const PARSE_ERRORS_FILENAME = 'parse_errors.jsonl';

function pathEndsWithSeparator(output) {
  return output.endsWith('/') || output.endsWith('\\');
}

function parseErrorsOutputPath(output) {
  if (!output)
    return null;

  const existingOutput = input_exists(output);
  if (existingOutput)
    return is_directory(output) ? path.join(output, PARSE_ERRORS_FILENAME) : output;

  if (pathEndsWithSeparator(output))
    return path.join(output, PARSE_ERRORS_FILENAME);

  return output;
}

function defaultParseErrorsOutputPath(output) {
  if (!output)
    return null;

  const existingOutput = input_exists(output);
  if (existingOutput && is_directory(output))
    return path.join(output, PARSE_ERRORS_FILENAME);

  if (pathEndsWithSeparator(output))
    return path.join(output, PARSE_ERRORS_FILENAME);

  return path.join(path.dirname(output), PARSE_ERRORS_FILENAME);
}

function writeParseErrors(output, parseErrors) {
  const outputPath = parseErrorsOutputPath(output);
  if (!outputPath)
    return;

  const body = parseErrors.map(error => JSON.stringify(error)).join('\n');
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, body ? `${body}\n` : '');
}

export default async function run(options, forCli = false) {

  await _i18n(); // wait for the _i18n function to complete

  if (!input_exists(options.input)) {
    const err = 'Input does not exist!';
    if (forCli) {
      console.error(chalk.red(err));
      process.exit(1);
    }
    else throw new Error(err);
  }

  // Load
  let loader;
  const generatedAt = new Date().toISOString();

  if(is_directory(options.input)){
    loader = new LoaderDirectory();
  }else{
    loader = (extension(options.input) === 'asar') ? new LoaderAsar() : new LoaderFile();
  }

  await loader.load(options.input);
  const electronVersion = options.electronVersionOverride || loader.electronVersion;
  options.electronVersionSource = options.electronVersionOverride ? 'cli' : loader.electronVersionSource;
  const versionContext = createVersionContext({
    electronVersion,
    electronVersionSource: options.electronVersionSource,
    electronVersionOverride: options.electronVersionOverride
  });
  const fuseContext = createFuseContext(options.fuseContext);
  if (!versionContext.known)
    logger.warn(__('electronVersionError'));

  if (options.severitySet) {
    if (!severity.hasOwnProperty(options.severitySet.toUpperCase())) {
      const err = __('severityLevelError');
      if (forCli) {
        console.error(chalk.red(err));
        process.exit(1);
      } else throw new Error(err);
    } else options.severitySet = severity[options.severitySet.toUpperCase()];
  } else options.severitySet = severity["INFORMATIONAL"]; // default to lowest

  if (options.confidenceSet) {
    if (!confidence.hasOwnProperty(options.confidenceSet.toUpperCase())) {
      const err = __('confidenceLevelError');
      if (forCli) {
        console.error(chalk.red(err));
        process.exit(1);
      } else throw new Error(err);
    } else options.confidenceSet = confidence[options.confidenceSet.toUpperCase()];
  } else options.confidenceSet = confidence["TENTATIVE"]; // default to lowest

  // Normalize the user-provided list. They should be already normalized if coming from the index.js,
  // but this is not granted in case Electronegativity is used programmatically
  options.customScan = (options.customScan || []).map(c => c.toLowerCase());
  options.excludeFromScan = (options.excludeFromScan || []).map(c => c.toLowerCase());
  const requestedCustomScan = Array.from(options.customScan);
  const requestedExcludeFromScan = Array.from(options.excludeFromScan);

  // Parser options initialization
  const scannerRoot = is_directory(options.input) ? options.input : path.dirname(options.input);
  const parser = new Parser(false, true, {
    scannerRoot,
    sourceMapExists: file => loader.file_exists(file)
  });

  if (options.parserPlugins && Array.isArray(options.parserPlugins) && options.parserPlugins.length > 0) {
    options.parserPlugins.forEach(plugin => parser.addPlugin(plugin));
  }

  // Global Checker initialization
  const globalChecker = new GlobalChecks(options.customScan, options.excludeFromScan, options.electronUpgrade);

  // Custom/Exclusion Scans initialization
  if (options.customScan.length > 0) options.customScan = options.customScan.filter(r => !r.includes('globalcheck')).concat(globalChecker.dependencies);
  if (options.excludeFromScan.length > 0) options.excludeFromScan = options.excludeFromScan.filter(r => !r.includes('globalcheck'));
  options.customScan = options.customScan.filter(r => !isPreloadIpcAuditCheckName(r));
  options.excludeFromScan = options.excludeFromScan.filter(r => !isPreloadIpcAuditCheckName(r));
  options.customScan = options.customScan.filter(r => !isStaticTrustAuditCheckName(r));
  options.excludeFromScan = options.excludeFromScan.filter(r => !isStaticTrustAuditCheckName(r));

  // Finder initialization
  const noAtomicChecks = requestedCustomScan.length > 0 && options.customScan.length === 0;
  const finder = await new Finder(options.customScan, noAtomicChecks ? [] : options.excludeFromScan, options.electronUpgrade, noAtomicChecks);
  const filenames = [...loader.list_files];

  // Results' table initialization
  let issues = [];
  let errors = [];
  let parseErrors = [];
  let fileClassifications = {};
  const rendererInventoryCollector = new RendererInventoryCollector();
  const preloadIpcCollector = new PreloadIpcCollector({
    customScan: requestedCustomScan,
    excludeFromScan: requestedExcludeFromScan
  });
  const staticTrustCollector = new StaticTrustCollector({
    customScan: requestedCustomScan,
    excludeFromScan: requestedExcludeFromScan
  });
  let table = new Table({
    head: [__('tableCheckId'), __('tableAffectedFile'), __('tableLocation'), __('tableDescription')],
    colWidths:[undefined, undefined, undefined, 50], // necessary for wordWrap
    wordWrap: true
  });

  if (forCli) console.log(chalk.green(`${__('numberOfChecksLoaded', {total: globalChecker._enabled_checks.length+finder._enabled_checks.length, globalChecks: globalChecker._enabled_checks.length, atomicChecks: finder._enabled_checks.length})}`));

  let progress;
  let oldLog;
  let consoleArguments = [];
  if (forCli) {
    progress = new cliProgress.Bar({format: '{bar} {percentage}% | {value}/{total}'}, cliProgress.Presets.shades_grey);
    oldLog = console.log;
    console.log = function () {
      consoleArguments.push(arguments);
    };
  }

  try {
    if (forCli) progress.start(filenames.length, 0);

    for (const file of filenames) {
      if (forCli) progress.increment();

      try {
        const [type, data, content, warnings] = parser.parse(file, loader.load_buffer(file));
        if (data === null)
          continue;

        if (warnings !== undefined) {
          for (const warning of warnings) {
            errors.push({ file: file, message: warning.message, tolerable: true });
            parseErrors.push(parseErrorRecord(file, parser.getFileClassification(file), warning));
          }
        }

        fileClassifications[file] = parser.getFileClassification(file);
        const result = await finder.find(file, data, type, content, null, versionContext, fileClassifications[file]);
        rendererInventoryCollector.collect(file, type, data, content);
        preloadIpcCollector.collect(file, type, data, content, fileClassifications[file]);
        staticTrustCollector.collect(file, type, data, content, fileClassifications[file]);
        issues.push(...result);
      } catch (error) {
        const classification = parser.getFileClassification(file);
        fileClassifications[file] = classification;
        errors.push({ file: file, message: error.message, tolerable: false });
        parseErrors.push(parseErrorRecord(file, classification, error));
      }
    }

    if (forCli) progress.stop();
  }
  finally {
    if (forCli) {
      console.log = oldLog;
      for (let i = 0; i < consoleArguments.length; i++)
        console.log.apply(this, consoleArguments[i]);
    }
  }

  if (forCli) {
    for (const error of errors) {
      if (error.tolerable) console.log(chalk.yellow(`${__('tolerableErrorParsing', {file: error.file, message: error.message})}`));
      else console.error(chalk.red(`${__('errorParsing', {file: error.file, message: error.message})}`));
    }
  }

  // Second pass of checks (in "GlobalChecks")
  // Now that we have all the "naive" findings we may analyze them further to sort out false negatives
  // and false positives before presenting them in the final report (e.g. CSP)
  issues = await globalChecker.getResults(issues, options.output, fileClassifications);

  const preloadIpcResults = preloadIpcCollector.buildAuditResults();
  issues.push(...preloadIpcResults.issues);
  const staticTrustResults = staticTrustCollector.buildAuditResults();
  issues.push(...staticTrustResults.issues);

  // Adjust visibility
  issues = issues.filter(i => !i.hasOwnProperty('visibility') || (!i.visibility.inlineDisabled && !i.visibility.globalCheckDisabled));

  // adjust to Relative or Absolute path
  if (options.isRelative)
    issues.forEach(function(issue, i, issues) {
      issues[i].file = getRelativePath(options.input, issue.file);
    });

  const runMetadata = buildRunMetadata(options, versionContext, generatedAt, fuseContext);
  const findings = buildFindings(options.input, issues, versionContext, fuseContext);
  const rendererInventory = rendererInventoryCollector.buildComponentInventory();
  const inventory = buildInventory(options.input, fileClassifications, {
    records: rendererInventory.records.concat(preloadIpcResults.componentInventory.records, staticTrustResults.componentInventory.records),
    relationships: rendererInventory.relationships.concat(preloadIpcResults.componentInventory.relationships, staticTrustResults.componentInventory.relationships)
  });
  const hypotheses = buildHypotheses(options.input, staticTrustResults.hypotheses);
  const sarif = buildSarifDocument(options.isRelative ? options.input : null, findings);

  let rows = [];
  if (forCli) {
    for (const issue of issues) {
      if (
        issue.severity.value >= options.severitySet.value &&
        issue.confidence.value >= options.confidenceSet.value
      )
        rows.push([
          `${issue.id}${
            issue.manualReview ? chalk.bgRed(`\n*${__('reviewRequired')}*`) : ``
          }\n${issue.severity.format()} | ${issue.confidence.format()}`,
          issue.file,
          `${issue.location.line}:${issue.location.column}`,
          `${options.isVerbose ? issue.description + '\n' + issue.shortenedURL : issue.shortenedURL}`,
        ]);
    }
  }

  if (options.output)
    writeIssues(options.input, options.isRelative, options.output, issues, options.isSarif);

  writeParseErrors(options.parseErrorsOutput || defaultParseErrorsOutputPath(options.output), parseErrors);

  if (options.outputDir)
    writeOutputDirectory(options.outputDir, runMetadata, findings, inventory, hypotheses, parseErrors, sarif);

  if (forCli) {
    if (rows.length > 0) {
      table.push(...rows);
      console.log(table.toString());
    } else console.log(chalk.green(`\n${__('noIssuesFound')}`));
    console.log('\x1b[4m\x1b[36m%s\x1b[0m',`${__('tryElectroNg')}`);
  }
  else return {
    globalChecks: globalChecker._enabled_checks.length,
    atomicChecks: finder._enabled_checks.length,
    errors,
    parseErrors,
    fileClassifications,
    issues,
    schemaV1: {
      run: runMetadata,
      findings,
      inventory,
      hypotheses,
      sarif,
      contextPacketFilename: contextPacketFilename()
    }
  };
}
