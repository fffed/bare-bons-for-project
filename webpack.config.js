const HtmlWebpackPlugin = require('html-webpack-plugin');


module.exports = {
    entry: './src/index.js',
    
    plugins: [
      new HtmlWebpackPlugin()
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
  