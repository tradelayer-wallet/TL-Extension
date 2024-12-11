const esbuild = require('esbuild');
const path = require('path');
const wasmPlugin = require('esbuild-plugin-wasm').default;
const buffer = require('buffer/');

esbuild.build({
  entryPoints: ['./popup/popup.js'],
  bundle: true,
  outfile: 'dist/bundle.js', // Output file
  minify: true,  // Optional: Minify the output for production
  platform: 'browser',  // Ensuring it's bundled for the browser
  format: 'esm',
  external: ['stream', 'buffer', 'process'],  // Mark Node.js built-ins as external
  plugins: [
    {
      name: 'node-polyfills',
      setup(build) {
        build.onResolve({ filter: /^stream$/ }, () => {
          return { path: require.resolve('stream-browserify') };
        });
        build.onResolve({ filter: /^stream\/transform$/ }, () => {
        return { path: require.resolve('stream-browserify/transform') };
        });
        build.onResolve({ filter: /^cipher-base$/ }, () => {
          return { path: require.resolve('cipher-base') };
        })
        build.onResolve({ filter: /^buffer$/ }, () => {
          return { path: require.resolve('buffer/') };
        });
        build.onResolve({ filter: /^vm$/ }, () => {
          return { path: require.resolve('vm-browserify') };
        });
         build.onResolve({ filter: /^events$/ }, () => {
          return { path: require.resolve('events/') };
        });
      },
    },
    wasmPlugin()  // Add wasm plugin to handle WASM files
  ],
  target: 'esnext',  // For modern browser compatibility
  inject: [
    require.resolve('stream-browserify'),  // Polyfill for stream
    require.resolve('process/browser'),    // Polyfill for process
    './shims/global.js', 
    './shims/process-polyfill.js',  // Custom process polyfill
    path.resolve(__dirname, 'node_modules/buffer/index.js'),  // Polyfill for buffer
    path.resolve(__dirname, 'node_modules/events/events.js'),  // Polyfill for events
  ],
  loader: {
    '.js': 'jsx',  // Treat .js files as JSX
    '.wasm': 'binary',  // Ensure WASM files are handled as binary
    '.png': 'dataurl'  // Add PNG support (as data URL)
  },
  sourcemap: true,  // Enables source maps
  logLevel: 'debug',  // Useful for debugging
}).catch(() => process.exit(1));
