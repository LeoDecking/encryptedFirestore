"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
exports.__esModule = true;
var encrypted_firestore_1 = require("encrypted-firestore");
var Job = /** @class */ (function (_super) {
    __extends(Job, _super);
    function Job() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.collection = "jobs";
        _this.supersecretValue = 23;
        _this.properties = [""];
        return _this;
    }
    return Job;
}(encrypted_firestore_1.DatabaseObject));
var City = /** @class */ (function (_super) {
    __extends(City, _super);
    function City() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.collection = "cities";
        _this.cityName = "";
        return _this;
    }
    return City;
}(encrypted_firestore_1.DatabaseObject));
var App = /** @class */ (function (_super) {
    __extends(App, _super);
    function App() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.appName = "";
        _this.verifyKey = new encrypted_firestore_1.VerifyKey(App, "123");
        return _this;
    }
    App.app = new App();
    return App;
}(encrypted_firestore_1.DatabaseObject));
var city = new City(App.app);
var job = new Job(city);
console.log(job.getPath());
console.log(job);
