module.exports = function(config) {
  config.set({
    frameworks: ["mocha", "chai"],
    files: ["src/**/*.test.js"],
    plugins: [
      "karma-mocha",
      "karma-chai",
      "karma-chrome-launcher",
      "karma-webpack"
    ],
    reporters: ["progress"],
    logLevel: config.LOG_INFO,
    browsers: ["ChromeHeadless"],
    preprocessors: {
      "src/**/*.js": ["webpack"]
    },
    client: {
      mocha: {
        timeout: 6000 // 6 seconds - upped from 2 seconds
      }
    }
  });
};
