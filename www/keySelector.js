module.exports = {
    select: function (name, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "KeySelector", "select", [name]);
    }
};
