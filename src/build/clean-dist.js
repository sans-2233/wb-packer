const fs = require('fs');
const path = require('path');

const distPath = path.join(__dirname, '..', '..', 'dist');

try {
  fs.rmSync(distPath, {
    recursive: true,
    force: true,
    maxRetries: 10,
    retryDelay: 100
  });
} catch (e) {
  try {
    fs.rmSync(distPath, {
      recursive: true,
      force: true
    });
  } catch (e2) {}
}

