const path = require("path");

const name = "krypt-web";
const config = {
  mode: "production",
  entry: `./src/lib/index.js`,
  output: {
    path: path.resolve(__dirname, "dist"),
    filename: `${name}.min.js`,
    library: name,
    libraryTarget: "umd",
    globalObject: "this"
  },
  module: {
    rules: [
      {
        test: /(\.jsx|\.js)$/,
        loader: "babel-loader",
        exclude: /(node_modules)/
      },
      {
        test: /(\.js)$/,
        loader: "eslint-loader",
        exclude: /node_modules/
      }
    ]
  }
};

module.exports = config;
