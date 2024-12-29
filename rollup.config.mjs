// rollup.config.js
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
  input: 'index.js',
  output: {
    file: 'dist/bitcoinjs.js',
    format: 'umd',
    name: 'bitcoin',    // the UMD global name
  },
  plugins: [
    resolve({ browser: true }), // so it finds "bitcoinjs-lib" in node_modules
    commonjs(),                 // convert commonjs to ESM
  ],
};
