import { sourceTypes, sourceExtensions } from './types';
import { Parser } from './parser';
import { classifyFile, parseErrorRecord } from './file_classification';

module.exports.sourceTypes = sourceTypes;
module.exports.sourceExtensions = sourceExtensions;
module.exports.Parser = Parser;
module.exports.classifyFile = classifyFile;
module.exports.parseErrorRecord = parseErrorRecord;
