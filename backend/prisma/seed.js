import { PrismaClient } from '@prisma/client';
import defaultProviders from '../src/config/providers.js';

const prisma = new PrismaClient();

async function main() {
  console.log('Starting database seed...');

  // Clear existing data (optional - comment out if you want to keep data)
  // await prisma.finding.deleteMany();
  // await prisma.subdomain.deleteMany();
  // await prisma.scan.deleteMany();
  // await prisma.provider.deleteMany();
  // await prisma.report.deleteMany();
  // await prisma.statistics.deleteMany();

  // Seed providers
  console.log('Seeding providers...');
  for (const provider of defaultProviders) {
    await prisma.provider.upsert({
      where: { name: provider.name },
      update: {
        cname: provider.cname,
        fingerprints: JSON.stringify(provider.fingerprints),
        httpCodes: JSON.stringify(provider.httpCodes),
        active: provider.active
      },
      create: {
        name: provider.name,
        cname: provider.cname,
        fingerprints: JSON.stringify(provider.fingerprints),
        httpCodes: JSON.stringify(provider.httpCodes),
        active: provider.active,
        detectionsCount: provider.detectionsCount
      }
    });
    console.log(`  ✓ ${provider.name}`);
  }

  console.log('\nDatabase seeded successfully! ✨');
  console.log(`Total providers: ${defaultProviders.length}`);
}

main()
  .catch((e) => {
    console.error('Seed error:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
