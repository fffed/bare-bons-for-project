const HtmlWebpackPlugin = require('html-webpack-plugin');


module.exports = {
    entry: './src/index.js',

    plugins: [
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
  