import logger from 'winston';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { Finder } from '../src/finder';
import run from '../src/runner';

logger.addColors({
  debug : 'green',
  info : 'cyan',
  silly : 'magenta',
  warn : 'yellow',
  error : 'red'
});

logger.remove(logger.transports.Console);
logger.add(logger.transports.Console, {colorize : true, level : 'silly'});

let chai = require('chai');
let should = chai.should();

import { LoaderFile } from '../src/loader';
import { Parser, classifyFile, parseErrorRecord } from '../src/parser';

let test_files = new Map()
  .set('html', 'test/file_formats/test.html')
  .set('ts', 'test/file_formats/test.ts')
  .set('js', 'test/file_formats/test.js')
  .set('esprima', 'test/file_formats/esprima.js')
  .set('babel', 'test/file_formats/babel.js')
  .set('modern', 'test/file_formats/modern.js')
  .set('tsx', 'test/file_formats/modern.tsx')
  .set('broken', 'test/file_formats/broken.js')
  .set('bundle', 'test/file_formats/app.bundle.js');

function parseFile(file, parser, finder) {
  let loader = new LoaderFile();
  loader.load(test_files.get(file));
  let filename = [...loader.list_files][0];
  let content = loader.load_buffer(filename);

  let output = null;

  it('does not Throw', async () => {
    output = parser.parse(filename, content);
    await finder.find(filename, output[1], output[0], content);
  });

  it('returns an Array', () => {
    output.should.be.a('Array');
  });

  it('returns an Array of length 4', () => {
    output.length.should.equal(4);
  });

  it('parsed source type should not be null', () => {
    should.exist(output[0]);
  });

  it('parsed data should not be null', () => {
    should.exist(output[1]);
  });
}

describe('Parser', () => {
  let parser = new Parser(false, true);
  let finder = new Finder();

  describe('Parse JavaScript', () => {
    parseFile('js', parser, finder);
  });

  describe('Parse JS babel cannot', () => {
    parseFile('esprima', parser, finder);
  });

  describe('Parse JS esprima cannot', () => {
    parseFile('babel', parser, finder);
  });

  describe('Parse TypeScript', () => {
    parseFile('ts', parser, finder);
  });

  describe('Parse modern JavaScript', () => {
    parseFile('modern', parser, finder);
  });

  describe('Parse TSX', () => {
    parseFile('tsx', parser, finder);
  });

  describe('File classification', () => {
    function readParseErrorRecords(output) {
      return fs.readFileSync(output, 'utf8').trim().split('\n').map(line => JSON.parse(line));
    }

    async function runBrokenParseErrors(output) {
      return run({
        input: path.resolve(test_files.get('broken')),
        parseErrorsOutput: output,
        customScan: [],
        excludeFromScan: []
      });
    }

    it('classifies bundled files and source maps', () => {
      let file = test_files.get('bundle');
      let content = fs.readFileSync(file);
      let classification = classifyFile(file, content, { parserStatus: 'ok' });

      classification.is_bundle.should.equal(true);
      classification.vendor_or_generated.should.equal(true);
      classification.source_map_present.should.equal(true);
      classification.source_map_available.should.equal(true);
      classification.parser_status.should.equal('ok');
    });

    it('does not classify renderer paths as bundles by name alone', () => {
      let classification = classifyFile('src/renderer/index.js', 'const app = require("electron");', { parserStatus: 'ok' });

      classification.is_bundle.should.equal(false);
    });

    it('preserves direct classification behavior without a scanner root', () => {
      let content = 'const app = require("electron");';

      classifyFile('/tmp/my-bundle-app/src/main.js', content, { parserStatus: 'ok' }).is_bundle.should.equal(true);
      classifyFile('/tmp/dist/src/main.js', content, { parserStatus: 'ok' }).vendor_or_generated.should.equal(true);
    });

    it('does not classify files by bundle, vendor, dist, or build scanner root names', () => {
      let content = 'const app = require("electron");';
      let parentNames = ['my-bundle-app', 'vendor-work', 'dist', 'build'];

      for (const parentName of parentNames) {
        let scannerRoot = path.join(os.tmpdir(), parentName);
        let file = path.join(scannerRoot, 'src', 'main.js');
        let scopedParser = new Parser(false, true, { scannerRoot });

        scopedParser.parse(file, content);
        let classification = scopedParser.getFileClassification(file);

        classification.is_bundle.should.equal(false);
        classification.vendor_or_generated.should.equal(false);
      }
    });

    it('uses loader-aware source map availability for virtual paths', () => {
      let content = 'console.log("mapped");\n//# sourceMappingURL=index.js.map';
      let classification = classifyFile('src/renderer/index.js', content, {
        parserStatus: 'ok',
        sourceMapExists: file => file === 'src/renderer/index.js.map'
      });

      classification.source_map_present.should.equal(true);
      classification.source_map_available.should.equal(true);
    });

    it('stores parser status on successful parses', () => {
      let file = test_files.get('modern');
      let content = fs.readFileSync(file);
      let output = parser.parse(file, content);
      let classification = parser.getFileClassification(file);

      output.length.should.equal(4);
      classification.parser_status.should.equal('ok');
      output[1].fileClassification.should.equal(classification);
    });

    it('stores parser status on parse errors without changing throw behavior', () => {
      let file = test_files.get('broken');
      let content = fs.readFileSync(file);

      (() => parser.parse(file, content)).should.throw();
      parser.getFileClassification(file).parser_status.should.equal('error');
    });

    it('creates parse error records without a file classification', () => {
      let record = parseErrorRecord('unreadable.js', undefined, new Error('read failed'));

      record.parser_status.should.equal('error');
      record.file_classification.is_minified.should.equal(false);
      record.file_classification.is_bundle.should.equal(false);
      record.file_classification.vendor_or_generated.should.equal(false);
      record.file_classification.source_map_present.should.equal(false);
      record.file_classification.source_map_available.should.equal(false);
      record.file_classification.parser_status.should.equal('error');
    });

    it('records loader failures before parser classification exists', async function () {
      this.timeout(10000);

      let originalLoadBuffer = LoaderFile.prototype.load_buffer;
      LoaderFile.prototype.load_buffer = function () {
        throw new Error('simulated loader read failure');
      };

      try {
        let outputRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-loader-error-'));
        let output = path.join(outputRoot, 'parse_errors.jsonl');
        let result = await runBrokenParseErrors(output);

        result.errors.length.should.equal(1);
        result.errors[0].message.should.equal('simulated loader read failure');
        result.parseErrors.length.should.equal(1);
        result.parseErrors[0].parser_status.should.equal('error');
        result.parseErrors[0].file_classification.is_minified.should.equal(false);
        result.parseErrors[0].file_classification.is_bundle.should.equal(false);
        result.parseErrors[0].file_classification.vendor_or_generated.should.equal(false);
        result.parseErrors[0].file_classification.source_map_present.should.equal(false);
        result.parseErrors[0].file_classification.source_map_available.should.equal(false);
        fs.existsSync(output).should.equal(true);
      } finally {
        LoaderFile.prototype.load_buffer = originalLoadBuffer;
      }
    });

    it('writes parser errors beside regular output without overwriting findings output', async function () {
      this.timeout(10000);

      let outputRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-parse-errors-output-dir-'));
      let output = path.join(outputRoot, 'results.csv');
      let parseErrorsOutput = path.join(outputRoot, 'parse_errors.jsonl');

      let result = await run({
        input: path.resolve(test_files.get('broken')),
        output,
        customScan: [],
        excludeFromScan: []
      });

      result.parseErrors.length.should.equal(1);
      fs.existsSync(output).should.equal(true);
      fs.existsSync(parseErrorsOutput).should.equal(true);
      fs.statSync(output).isFile().should.equal(true);
      let records = readParseErrorRecords(parseErrorsOutput);
      records[0].file.should.include('broken.js');
      records[0].parser_status.should.equal('error');
    });

    it('writes parser errors as jsonl when requested', async function () {
      this.timeout(10000);

      let outputRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-parse-errors-'));
      let output = path.join(outputRoot, 'nested', 'parse_errors.jsonl');

      let result = await runBrokenParseErrors(output);

      result.parseErrors.length.should.equal(1);
      fs.existsSync(output).should.equal(true);
      let records = readParseErrorRecords(output);
      records[0].file.should.include('broken.js');
      records[0].parser_status.should.equal('error');
    });

    it('writes parser errors to parse_errors.jsonl in an existing directory', async function () {
      this.timeout(10000);

      let outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-parse-errors-dir-'));
      let output = path.join(outputDir, 'parse_errors.jsonl');

      let result = await runBrokenParseErrors(outputDir);

      result.parseErrors.length.should.equal(1);
      fs.existsSync(output).should.equal(true);
      let records = readParseErrorRecords(output);
      records[0].file.should.include('broken.js');
      records[0].parser_status.should.equal('error');
    });

    it('writes parser errors to parse_errors.jsonl in a newly-created directory with an explicit separator', async function () {
      this.timeout(10000);

      let outputRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-parse-errors-new-dir-'));
      let outputDir = path.join(outputRoot, 'nested', 'errors');
      let output = path.join(outputDir, 'parse_errors.jsonl');

      let result = await runBrokenParseErrors(`${outputDir}${path.sep}`);

      result.parseErrors.length.should.equal(1);
      fs.existsSync(output).should.equal(true);
      let records = readParseErrorRecords(output);
      records[0].file.should.include('broken.js');
      records[0].parser_status.should.equal('error');
    });

    it('treats nonexistent extensionless parse error output paths as files', async function () {
      this.timeout(10000);

      let outputRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'electro-parse-errors-file-'));
      let output = path.join(outputRoot, 'parse-errors');
      let nestedOutput = path.join(output, 'parse_errors.jsonl');

      let result = await runBrokenParseErrors(output);

      result.parseErrors.length.should.equal(1);
      fs.existsSync(output).should.equal(true);
      fs.statSync(output).isFile().should.equal(true);
      fs.existsSync(nestedOutput).should.equal(false);
      let records = readParseErrorRecords(output);
      records[0].file.should.include('broken.js');
      records[0].parser_status.should.equal('error');
    });
  });

  describe('Parse HTML', () => {
    let loader = new LoaderFile();
    loader.load(test_files.get('html'));
    let filename = [...loader.list_files][0];
    let content = loader.load_buffer(filename);

    let output = null;

    it('does not Throw', () => {
      (() => {
        output = parser.parse(filename, content);
      }).should.not.throw();
    });

    it('returns an Array', () => {
      output.should.be.a('Array');
    });

    it('returns an Array of length 4', () => {
      output.length.should.equal(4);
    });

    it('parsed source type should not be null', () => {
      should.exist(output[0]);
    });

    it('parsed data should not be null', () => {
      should.exist(output[1]);
    });

    it('parsed data should be a DOM', () => {
      output[1].html().should.include("<!DOCTYPE html>");
    });
  });

});
