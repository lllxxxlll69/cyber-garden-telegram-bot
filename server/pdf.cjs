const PDFDocument = require('pdfkit');
const path = require('node:path');
const font = path.join(__dirname, '../assets/fonts/JetBrainsMono-Regular.ttf');

function renderPdf(report) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margins: { top: 48, bottom: 64, left: 48, right: 48 }, bufferPages: true, info: { Title: report.title, Author: 'Cyber Garden' } });
    const chunks = [];
    doc.on('data', chunk => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    try {
      doc.font(font).fillColor('#183b32').fontSize(23).text('CYBER GARDEN');
      doc.moveDown(0.5).fontSize(17).text(report.title);
      doc.moveDown().fillColor('#4a5752').fontSize(9)
        .text(`Дата: ${new Date(report.created).toISOString()}`)
        .text(`Отчёт: ${report.id}`);
      doc.moveDown().fontSize(11).fillColor('#183b32').text(`Всего находок: ${report.findings.length}`);
      const levels = ['critical', 'high', 'medium', 'low', 'info'];
      doc.fontSize(9).text(levels.map(l => `${l}: ${report.findings.filter(f => f.severity === l).length}`).join(' | '));
      doc.moveDown(1.5);
      if (!report.findings.length) doc.text('Проверка завершена. Находок нет.');
      for (const [index, item] of report.findings.entries()) {
        if (doc.y > 640) doc.addPage();
        doc.fillColor(['critical', 'high'].includes(item.severity) ? '#a52b33' : '#183b32')
          .fontSize(12).text(`${index + 1}. [${item.severity.toUpperCase()}] ${item.title || item.rule}`);
        doc.moveDown(0.4).fillColor('#303c36').fontSize(9);
        if (item.file) doc.text(`${item.file}${item.line ? ':' + item.line : ''}`);
        if (item.rule) doc.text(`Правило: ${item.rule}`);
        if (item.reference) doc.text(`Идентификатор: ${item.reference}`);
        if (item.fix) doc.moveDown(0.4).text(`Исправление: ${item.fix}`);
        if (item.advice) doc.moveDown(0.4).text(`Рекомендация: ${item.advice}`);
        doc.moveDown(1.2);
      }
      const range = doc.bufferedPageRange();
      for (let i = 0; i < range.count; i++) {
        doc.switchToPage(i);
        const bottom = doc.page.margins.bottom;
        doc.page.margins.bottom = 0;
        doc.fillColor('#718078').fontSize(8).text(`${i + 1} / ${range.count}`, 48, 805, { lineBreak: false, align: 'right', width: 499 });
        doc.page.margins.bottom = bottom;
      }
      doc.end();
    } catch (error) { reject(error); doc.destroy(); }
  });
}
module.exports = { renderPdf };
