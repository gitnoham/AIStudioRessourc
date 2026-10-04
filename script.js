// script.js
import https from 'https';
import fs from 'fs';
import path from 'path';
import { Address4 } from 'ip-address';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const AWS_URL = 'https://ip-ranges.amazonaws.com/ip-ranges.json';
const OUTPUT_DIR = path.join(__dirname, 'aws_ips_output');

const TARGET_SERVICES = new Set([
  'CLOUDFRONT',
  'CLOUDFRONT_ORIGIN_FACING',
  'S3',
  'GLOBALACCELERATOR',
  'API_GATEWAY',
  // 'EC2',
  // 'AMAZON',
]);

if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

console.log('→ Téléchargement des plages AWS...');

https.get(AWS_URL, (res) => {
  let data = '';
  res.on('data', (chunk) => (data += chunk));
  res.on('end', () => {
    try {
      const json = JSON.parse(data);
      const prefixes = json.prefixes.filter((p) => TARGET_SERVICES.has(p.service));

      console.log(`→ ${prefixes.length} préfixes trouvés pour les services web`);
      console.log('→ Expansion en cours...\n');

      let total = 0;
      for (const p of prefixes) {
        total += expand(p);
      }

      console.log(`\n✅ Terminé ! Total IPs écrites : ${total.toLocaleString()}`);
      console.log(`Dossier : ${OUTPUT_DIR}`);
    } catch (err) {
      console.error('Erreur :', err.message);
    }
  });
}).on('error', (err) => {
  console.error('Erreur de téléchargement :', err.message);
});

function expand(p) {
  try {
    const addr = new Address4(p.ip_prefix);
    const start = addr.startAddress();
    const end = addr.endAddress();

    // Sécurité : ignore les préfixes trop gros (>/20 = > 1 million d'IPs)
    const size = Math.pow(2, 32 - addr.subnetMask);
    if (size > 1_048_576) {
      console.log(`  [skip] ${p.ip_prefix} trop gros (${size.toLocaleString()} IPs)`);
      return 0;
    }

    const filename = `${p.service.toLowerCase()}_${p.region}_${p.ip_prefix.replace(/\//g, '-')}.txt`;
    const filePath = path.join(OUTPUT_DIR, filename);
    const stream = fs.createWriteStream(filePath);

    let current = start;
    let count = 0;
    const endStr = end.correctForm();

    while (true) {
      stream.write(current.correctForm() + '\n');
      count++;

      if (current.correctForm() === endStr) break;

      // Méthode correcte : offset(1)
      current = current.offset(1);
    }

    stream.end();
    console.log(`  ✓ ${filename} → ${count.toLocaleString()} IPs`);
    return count;
  } catch (e) {
    console.error(`  [!] Erreur sur ${p.ip_prefix}:`, e.message);
    return 0;
  }
}