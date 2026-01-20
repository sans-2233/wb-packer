module.exports = {
  name: 'legal-notice-and-integrity',
  version: '1.0.0',
  hooks: {
    transformElectronMain (mainJS) {
      if (!mainJS || typeof mainJS !== 'string') return mainJS;
      if (mainJS.includes('WB_LEGAL_NOTICE_B64')) return mainJS;

      const noticeText = [
        '警告：',
        '如果继续破解、分发或传播本游戏的资源/程序，将采取法律措施。',
        '本版本包含完整性校验与取证标识。'
      ].join('\n');
      const noticeB64 = Buffer.from(noticeText, 'utf8').toString('base64');

      const injection = [
        `const WB_LEGAL_NOTICE_B64 = ${JSON.stringify(noticeB64)};`,
        `const wbDecodeB64 = (s) => Buffer.from(String(s || ''), 'base64').toString('utf8');`,
        `const wbShowLegalWarning = (detail) => {`,
        `  try {`,
        `    dialog.showMessageBoxSync({`,
        `      type: 'warning',`,
        `      title: 'Warning',`,
        `      message: wbDecodeB64(WB_LEGAL_NOTICE_B64),`,
        `      detail: detail ? String(detail) : ''`,
        `    });`,
        `  } catch (e) {}`,
        `};`
      ].join('\n') + '\n';

      const marker = 'const verifyIntegrity = () => {';
      if (!mainJS.includes(marker)) return mainJS;
      mainJS = mainJS.replace(marker, injection + marker);

      mainJS = mainJS.replace(/app\.exit\(2\);/g, `wbShowLegalWarning('Integrity check failed');\n    app.exit(2);`);
      return mainJS;
    }
  }
};

