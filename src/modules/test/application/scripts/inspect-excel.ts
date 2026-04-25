const XLSX = require('xlsx');
const path = require('path');

const filePath = path.join(process.cwd(), 'database', 'seeds', '2026.STAX.HR.Management.xlsx');
const workbook = XLSX.readFile(filePath);

console.log('--- DANH SÁCH SHEETS ---');
console.log(workbook.SheetNames);

workbook.SheetNames.forEach(sheetName => {
    console.log(`\n--- DỮ LIỆU MẪU SHEET: ${sheetName} ---`);
    const sheet = workbook.Sheets[sheetName];
    const json = XLSX.utils.sheet_to_json(sheet, { header: 1 });
    // In 5 dòng đầu
    json.slice(0, 5).forEach((row, index) => {
        console.log(`Dòng ${index}:`, row);
    });
});
