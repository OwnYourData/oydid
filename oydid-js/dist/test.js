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
// const createResponse = create().then(response => {
//     didAuth(response.id, response.docKey, "https://regapi.data-container.net").then(val => {
//         console.log(val.toString());
//     })
// })
const cipher_message = {
    value: "82ba7d8ec5800786d9ae1414cd70ba864f438051085be7834cbde39d093684f9f90a0d9a1ccd9b7337baa2e00a94ccbaf29b70acd391471b0a9cd27731cbd214ea98e1c5d11670e37a6b6b0eb1",
    nonce: "9266f52178bfa1df25fa16b6fb984e67e02c0a223ee34b33"
};
const private_key_hex = "001320d019a71ed168aab7f4bd0a686e7bf2c32ac243c1463642ebaa7d40a93ecb4aa3";
const private_key = (0, oydid_1.hexToMulti)(private_key_hex).then(key => {
    // console.log(key);
    (0, oydid_1.decrypt)(cipher_message, key).then(response => {
        console.log(response.toString());
    });
});
