/* eslint-disable @typescript-eslint/no-var-requires */
const path = require('path');
const webpack = require('webpack');

/** @type WebpackConfig */
const config = {
    mode: 'none', // this leaves the source code as close as possible to the original (when packaging we set this to 'production')
    target: 'node', // extensions run in a node context
    entry: {
        extension: './src/extension.ts'
    },
    output: {
        filename: '[name].js',
        path: path.join(__dirname, './dist'),
        libraryTarget: 'commonjs',
        devtoolModuleFilenameTemplate: '../../[resource-path]'
    },
    resolve: {
        mainFields: ['module', 'main'],
        extensions: ['.ts', '.js'], // support ts-files and js-files
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
    plugins: [
        new webpack.IgnorePlugin({
            resourceRegExp: /^((fs)|(path)|(os)|(crypto)|(source-map-support))$/,
            contextRegExp: /vs\/language\/typescript\/lib/
        })
    ],
    externals: {
        vscode: 'commonjs vscode' // ignored because it doesn't exist
    },
    performance: {
        hints: false
    },
    devtool: 'nosources-source-map' // create a source map that points to the original source file
};

module.exports = config;
