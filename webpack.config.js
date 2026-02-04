const path = require('path');

/** @type WebpackConfig */
const extensionConfig = {
  mode: 'none',
  target: 'node',
  entry: {
    extension: './src/extension.ts',
  },
  output: {
    filename: 'extension.js',
    path: path.join(__dirname, './dist'),
    libraryTarget: 'commonjs',
    devtoolModuleFilenameTemplate: '../../[resource-path]'
  },
  resolve: {
    mainFields: ['module', 'main'],
    extensions: ['.ts', '.js'],
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        exclude: /node_modules/,
        use: [
          {
            loader: 'ts-loader'
          }
        ]
      }
    ]
  },
  externals: {
    'vscode': 'commonjs vscode',
  },
  devtool: 'nosources-source-map',
};

module.exports = [ extensionConfig ];