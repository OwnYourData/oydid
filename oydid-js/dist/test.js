"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const oydid_1 = require("./oydid");
// try {
//     read("");
// } catch(e: any) {
//     console.log(e.toString());
// }
// create().then(response => {
//     console.log(JSON.stringify(response, null, 2));
// })
const response = (0, oydid_1.create)().then(response => {
    (0, oydid_1.did_auth)(response.id, response.docKey).then(val => {
        console.log(val.toString());
    });
});
