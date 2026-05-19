import {
  buildFindings,
  buildInventory,
  buildHypotheses,
  buildRunMetadata,
  buildSarifDocument
} from './schema';
import { contextPacketFilename, writeOutputDirectory } from './writer';

module.exports.buildFindings = buildFindings;
module.exports.buildHypotheses = buildHypotheses;
module.exports.buildInventory = buildInventory;
module.exports.buildRunMetadata = buildRunMetadata;
module.exports.buildSarifDocument = buildSarifDocument;
module.exports.contextPacketFilename = contextPacketFilename;
module.exports.writeOutputDirectory = writeOutputDirectory;
