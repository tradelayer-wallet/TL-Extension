const fs = require('fs');

function fixWindowError() {
  const file = './node_modules/tiny-secp256k1/lib/rand.browser.js';
  let fileData = fs.readFileSync(file, 'utf8');
  fileData = fileData.replace(/window\.crypto/g, 'crypto');
  fs.writeFileSync(file, fileData, 'utf8');
}

// Call the function
fixWindowError();
