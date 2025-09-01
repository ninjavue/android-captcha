const fs = require('fs');
const path = require('path');
const VirusHash = require('../models/VirusHash');

const loadVirusHashes = async () => {
  try {
    const virusFilePath = path.join(__dirname, '..', 'virus.txt');
    
    if (!fs.existsSync(virusFilePath)) {
      console.log('virus.txt fayli topilmadi');
      return;
    }

    console.log('virus.txt faylini o\'qish boshlandi...');
    
    const fileContent = fs.readFileSync(virusFilePath, 'utf8');
    const hashes = fileContent
      .split('\n')
      .map(hash => hash.trim())
      .filter(hash => hash.length > 0 && hash.length >= 32); 

    console.log(`${hashes.length} ta hash topildi`);

    let savedCount = 0;
    let skippedCount = 0;
    let errorCount = 0;

    const batchSize = 1000;
    const batches = [];
    
    for (let i = 0; i < hashes.length; i += batchSize) {
      batches.push(hashes.slice(i, i + batchSize));
    }

    console.log(`${batches.length} ta batch yaratildi`);

    for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
      const batch = batches[batchIndex];
      console.log(`Batch ${batchIndex + 1}/${batches.length} qayta ishlanmoqda...`);
      
      const hashChecks = await Promise.allSettled(
        batch.map(hash => VirusHash.findOne({ hash }).select('hash'))
      );

      const newHashes = [];
      for (let i = 0; i < batch.length; i++) {
        const checkResult = hashChecks[i];
        if (checkResult.status === 'fulfilled' && !checkResult.value) {
          newHashes.push({ hash: batch[i] });
        } else if (checkResult.status === 'fulfilled') {
          skippedCount++;
        } else {
          errorCount++;
          console.error(`Hash tekshirishda xatolik: ${batch[i]}`, checkResult.reason);
        }
      }

      if (newHashes.length > 0) {
        try {
          await VirusHash.insertMany(newHashes, { ordered: false });
          savedCount += newHashes.length;
          console.log(`Batch ${batchIndex + 1}: ${newHashes.length} ta yangi hash qo'shildi`);
        } catch (error) {
          if (error.code === 11000) {
            const duplicateErrors = error.writeErrors || [];
            const successfulInserts = newHashes.length - duplicateErrors.length;
            savedCount += successfulInserts;
            skippedCount += duplicateErrors.length;
            console.log(`Batch ${batchIndex + 1}: ${successfulInserts} ta hash qo'shildi, ${duplicateErrors.length} ta duplicate`);
          } else {
            console.error(`Batch ${batchIndex + 1} saqlashda xatolik:`, error.message);
            errorCount += newHashes.length;
          }
        }
      }
    }

    console.log(`\n=== Virus hashlari yuklash yakunlandi ===`);
    console.log(`- Yangi qo'shilgan: ${savedCount}`);
    console.log(`- O'tkazib yuborilgan (mavjud): ${skippedCount}`);
    console.log(`- Xatoliklar: ${errorCount}`);
    console.log(`- Jami qayta ishlangan: ${savedCount + skippedCount + errorCount}`);
    console.log(`- Fayldagi hashlar: ${hashes.length}`);

  } catch (error) {
    console.error('Virus hashlarini yuklashda xatolik:', error.message);
  }
};

module.exports = loadVirusHashes; 