const JavaScriptObfuscator = require('javascript-obfuscator');
const fs = require('fs');
const path = require('path');

const filesToObfuscate = [
  { src: 'src/config.js', dest: 'config.js' },
  { src: 'src/security.js', dest: 'security.js' },
  { src: 'src/main.js', dest: 'main.js' }
];

const obfuscationOptions = {
  compact: true,
  controlFlowFlattening: false,
  deadCodeInjection: false,
  debugProtection: false,
  debugProtectionInterval: 0,
  disableConsoleOutput: false,
  identifierNamesGenerator: 'hexadecimal',
  log: false,
  numbersToExpressions: false,
  renameGlobals: false,
  selfDefending: false,
  simplify: true,
  splitStrings: false,
  stringArray: true,
  stringArrayCallsTransform: false,
  stringArrayCallsTransformThreshold: 0.5,
  stringArrayEncoding: [],
  stringArrayIndexShift: true,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayWrappersCount: 1,
  stringArrayWrappersChainedCalls: true,
  stringArrayWrappersParametersMaxCount: 2,
  stringArrayWrappersType: 'variable',
  stringArrayThreshold: 0.75,
  unicodeEscapeSequence: false
};

function build() {
  console.log('Starting JavaScript obfuscation...');
  for (const file of filesToObfuscate) {
    const srcPath = path.resolve(__dirname, file.src);
    const destPath = path.resolve(__dirname, file.dest);

    if (!fs.existsSync(srcPath)) {
      console.error(`Source file not found: ${file.src}`);
      process.exit(1);
    }

    console.log(`Obfuscating ${file.src} -> ${file.dest}...`);
    const code = fs.readFileSync(srcPath, 'utf8');
    const obfuscationResult = JavaScriptObfuscator.obfuscate(code, obfuscationOptions);
    fs.writeFileSync(destPath, obfuscationResult.getObfuscatedCode(), 'utf8');
    console.log(`Successfully obfuscated ${file.dest}`);
  }
  console.log('All JavaScript files obfuscated successfully.');
}

build();
