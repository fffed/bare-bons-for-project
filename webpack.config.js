const { CleanWebpackPlugin } = require('clean-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');


module.exports = {
    entry: './src/index.js',

    devtool: 'source-map',

    plugins: [
      new CleanWebpackPlugin(),
      new HtmlWebpackPlugin({
        title: 'Hello Webpack bundled JavaScript Project',
        template: './src/index.html'
    })
    ],

    output: {
      path: __dirname + '/dist',
      publicPath: '/',
      filename: 'bundle.js'
    },
    
    devServer: {
      contentBase: './dist'
    }
  };
  