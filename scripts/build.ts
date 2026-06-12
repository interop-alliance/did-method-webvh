import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import type { BuildOptions, Plugin } from 'esbuild';
import * as esbuild from 'esbuild';
import pkg from '../package.json';

// Library builds
const browserConfig: BuildOptions = {
  entryPoints: ['./src/index.ts'],
  bundle: true,
  minify: true,
  sourcemap: 'external',
  platform: 'browser',
  format: 'esm',
  outdir: './dist/browser',
  define: {
    'process.env.NODE_ENV': '"production"',
    global: 'window',
  },
};

const esmConfig: BuildOptions = {
  entryPoints: ['./src/index.ts'],
  bundle: true,
  minify: false,
  sourcemap: 'external',
  platform: 'node',
  format: 'esm',
  outdir: './dist/esm',
};

const dynamicImportToCjsPlugin: Plugin = {
  name: 'dynamic-import-to-cjs',
  setup(build) {
    build.onLoad({ filter: /\.[jt]s$/ }, async (args) => {
      const contents = readFileSync(args.path, 'utf8');
      // Replace dynamic imports with requires
      const transformed = contents.replace(/await\s+import\((.*?)\)/g, 'require($1)');
      return { contents: transformed, loader: args.path.endsWith('.ts') ? 'ts' : 'js' };
    });
  },
};

const cjsConfig: BuildOptions = {
  entryPoints: ['./src/index.ts'],
  bundle: true,
  minify: false,
  sourcemap: 'external',
  platform: 'node',
  format: 'cjs',
  outdir: './dist/cjs',
  plugins: [dynamicImportToCjsPlugin],
};

const cliConfig: BuildOptions = {
  entryPoints: ['./src/cli.ts'],
  bundle: true,
  minify: false,
  sourcemap: 'external',
  platform: 'node',
  format: 'esm',
  outfile: './dist/cli/didwebvh.js',
};

async function ensureDir(dir: string) {
  await mkdir(dir, { recursive: true });
}

function createDistPackageJson() {
  // Create a simplified package.json for distribution
  const distPkg: any = {
    name: pkg.name,
    version: pkg.version,
    type: 'module',
    'react-native': './cjs/index.cjs',
    main: './cjs/index.cjs',
    module: './esm/index.js',
    browser: './browser/index.js',
    types: './types/index.d.ts',
    bin: {
      didwebvh: './cli/didwebvh.js',
    },
    files: ['cjs', 'esm', 'browser', 'cli', 'types'],
    exports: {
      '.': {
        types: './types/index.d.ts',
        'react-native': './cjs/index.cjs',
        browser: './browser/index.js',
        import: './esm/index.js',
        require: './cjs/index.cjs',
      },
      './types': {
        types: './types/types.d.ts',
      },
    },
    dependencies: pkg.dependencies,
  };

  // Only add optional fields if they exist in the source package.json
  if ('description' in pkg) distPkg.description = pkg.description;
  if ('author' in pkg) distPkg.author = pkg.author;
  if ('license' in pkg) distPkg.license = pkg.license;
  if ('repository' in pkg) distPkg.repository = pkg.repository;
  if ('bugs' in pkg) distPkg.bugs = pkg.bugs;
  if ('homepage' in pkg) distPkg.homepage = pkg.homepage;

  writeFileSync('./dist/package.json', JSON.stringify(distPkg, null, 2));
}

function createDistReadme() {
  // Read the main README
  const readme = readFileSync('./README.md', 'utf-8');

  // Add distribution-specific information
  const distReadme = `# ${pkg.name}

${readme}

## Distribution Package Structure

This package includes:
- \`node/\` - Node.js ESM bundle
- \`browser/\` - Browser ESM bundle
- \`cli/\` - Command-line interface
- \`types/\` - TypeScript type declarations
`;

  writeFileSync('./dist/README.md', distReadme);
}

async function renameCjsFiles() {
  const cjsDir = './dist/cjs';
  const files = readdirSync(cjsDir);

  await Promise.all(
    files
      .filter((file) => file.endsWith('.js'))
      .map((file) => renameSync(`${cjsDir}/${file}`, `${cjsDir}/${file.replace('.js', '.cjs')}`))
  );
}

async function runBuild(name: string, config: BuildOptions) {
  console.log(`\nBuilding ${name} bundle...`);
  try {
    await esbuild.build(config);
  } catch (error) {
    console.error(`${name} build failed:`, error);
    process.exit(1);
  }
}

async function build() {
  // Clean dist directory first
  rmSync('dist', { recursive: true, force: true });

  // Create output directories
  console.log('\nCreating output directories...');
  await Promise.all([
    ensureDir('./dist/cjs'),
    ensureDir('./dist/esm'),
    ensureDir('./dist/browser'),
    ensureDir('./dist/cli'),
    ensureDir('./dist/types'),
  ]);

  await runBuild('ESM', esmConfig);
  await runBuild('CJS', cjsConfig);

  // Rename CJS files to .cjs
  console.log('\nRenaming CJS files...');
  await renameCjsFiles();

  await runBuild('Browser', browserConfig);
  await runBuild('CLI', cliConfig);

  // Generate type declarations
  console.log('\nGenerating TypeScript declarations...');

  // Create a temporary tsconfig for declarations
  const declarationConfig = {
    compilerOptions: {
      declaration: true,
      emitDeclarationOnly: true,
      declarationDir: './dist/types',
      moduleResolution: 'bundler',
      module: 'esnext',
      target: 'esnext',
      allowSyntheticDefaultImports: true,
      esModuleInterop: true,
      skipLibCheck: true,
      rootDir: './src',
    },
    include: ['src/**/*'],
    exclude: ['node_modules', 'dist', 'test'],
  };

  writeFileSync('tsconfig.declarations.json', JSON.stringify(declarationConfig, null, 2));

  const tscResult = spawnSync('npx', ['tsc', '--project', 'tsconfig.declarations.json'], {
    stdio: 'inherit',
  });

  // Clean up temporary config
  rmSync('tsconfig.declarations.json');

  if (tscResult.status !== 0) {
    console.error('TypeScript compilation failed');
    process.exit(1);
  }

  // Make CLI executable
  chmodSync('dist/cli/didwebvh.js', 0o755);

  // Create distribution package.json and README
  console.log('\nCreating distribution package files...');
  createDistPackageJson();
  createDistReadme();

  // Verify output directories exist and have content
  const dirs = ['cjs', 'esm', 'browser', 'cli', 'types'].map((dir) => `dist/${dir}`);
  for (const dir of dirs) {
    if (!existsSync(dir)) {
      console.error(`Missing output directory: ${dir}`);
      process.exit(1);
    }
    const files = readdirSync(dir);
    if (files.length === 0) {
      console.error(`No files in output directory: ${dir}`);
      process.exit(1);
    }
    console.log(`\nFiles in ${dir}:`, files);
  }

  console.log('\nBuild completed successfully!');
}

await build();
