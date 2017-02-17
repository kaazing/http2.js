// Check what enviroment it is

var env = {};
env.isNode = function () {
    return (typeof window === 'undefined');
};

module.exports = env;